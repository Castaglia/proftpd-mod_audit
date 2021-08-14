/*
 * ProFTPD - mod_audit
 * Copyright (c) 2008-2011 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Libraries: -lbsm$
 */

#include "mod_audit.h"

module audit_module;

static int audit_engine = FALSE;
static au_event_t audit_event_id = AUE_ftpd;
static int audit_logfd = -1;

#ifdef HAVE_SETAUDIT_ADDR
static au_tid_addr_t audit_tid;
#else
static au_tid_t audit_tid;
#endif /* !HAVE_SETAUDIT_ADDR */

typedef enum {
  PR_AUDIT_EVENT_AUTH_OK_NO_PASS = 1,
  PR_AUDIT_EVENT_AUTH_RFC2228_OK,
  PR_AUDIT_EVENT_AUTH_OK,
  PR_AUDIT_EVENT_AUTH_ERROR,
  PR_AUDIT_EVENT_AUTH_BADPWD,
  PR_AUDIT_EVENT_AUTH_AGEPWD,
  PR_AUDIT_EVENT_AUTH_NOPWD,
  PR_AUDIT_EVENT_AUTH_DISABLEDPWD,
  PR_AUDIT_EVENT_EXCEEDED_MAX_LOGIN_ATTEMPTS,
  PR_AUDIT_EVENT_ROOT_LOGIN_DENIED,
  PR_AUDIT_EVENT_CONNECTION_CLOSE

} audit_event_e;

struct audit_event_info {
  audit_event_e event_type;
  int success_flag;
  int event_errno;
  const char *event_name;
  const char *event_text;
};

static struct audit_event_info audit_events[] = {
  { PR_AUDIT_EVENT_AUTH_OK_NO_PASS,		AU_PRS_SUCCESS,
    0, "AUTH_OK_NO_PASS",	"Authenticated without password" },

  { PR_AUDIT_EVENT_AUTH_RFC2228_OK,		AU_PRS_SUCCESS,
    0, "AUTH_RFC2228_OK",	"Authenticated via RFC2228 mechanism" },

  { PR_AUDIT_EVENT_AUTH_OK,			AU_PRS_SUCCESS,
    0, "AUTH_OK",		"Authenticated with password" },

  { PR_AUDIT_EVENT_AUTH_ERROR,			AU_PRS_FAILURE,
    1, "AUTH_ERROR",	"Authentication error" },

  { PR_AUDIT_EVENT_AUTH_BADPWD,			AU_PRS_FAILURE,
    4, "AUTH_BADPWD",	"Authentication failed: Bad password" },

  { PR_AUDIT_EVENT_AUTH_AGEPWD,			AU_PRS_FAILURE,
    4, "AUTH_AGEPWD",	"Authentication failed: Password too old" },

  { PR_AUDIT_EVENT_AUTH_NOPWD,			AU_PRS_FAILURE,
    3, "AUTH_NOPWD",	"Authentication failed: No such user" },

  { PR_AUDIT_EVENT_AUTH_DISABLEDPWD,		AU_PRS_FAILURE,
    3, "AUTH_DISABLEDPWD",	"Authentication failed: Disabled account" },

  { PR_AUDIT_EVENT_EXCEEDED_MAX_LOGIN_ATTEMPTS,	AU_PRS_FAILURE,
    1, "EXCEEDED_MAX_LOGIN_ATTEMPTS",	"Login failed: Exceeded max attempts" },

  { PR_AUDIT_EVENT_ROOT_LOGIN_DENIED,		AU_PRS_FAILURE,
    2, "ROOT_LOGIN_DENIED",	"Login failed: Root login denied" },

  { PR_AUDIT_EVENT_CONNECTION_CLOSE,		AU_PRS_SUCCESS,
    0, "CONNECTION_CLOSE",		"Connection closed" },

  { 0, -1, -1, NULL, NULL },
};

/* Returne the "error number" for the given event, for use in au_to_return(3).
 */
static int get_event_errno(audit_event_e event_type) {
  register unsigned int i;

  for (i = 0; audit_events[i].event_type; i++) {
    if (audit_events[i].event_type == event_type) {
      return audit_events[i].event_errno;
    }
  }

  return 0;
}

/* Returns the name of the given event. */
static const char *get_event_name(audit_event_e event_type) {
  register unsigned int i;

  for (i = 0; audit_events[i].event_type; i++) {
    if (audit_events[i].event_type == event_type) {
      return audit_events[i].event_name;
    }
  }

  errno = ENOENT;
  return NULL;
}

/* Returns AU_PRS_SUCCESS or AU_PRS_FAILURE, depending on whether the given
 * event is a "success" event or a "failure" event.
 */
static int get_event_success_flag(audit_event_e event_type) {
  register unsigned int i;

  for (i = 0; audit_events[i].event_type; i++) {
    if (audit_events[i].event_type == event_type) {
      return audit_events[i].success_flag;
    }
  }

  errno = ENOENT;
  return -1;
}

/* Returns the textual description of the given event. */
static char *get_event_text(audit_event_e event_type) {
  register unsigned int i;

  for (i = 0; audit_events[i].event_type; i++) {
    if (audit_events[i].event_type == event_type) {
      return (char *) audit_events[i].event_text;
    }
  }

  errno = ENOENT;
  return NULL;
}

/* The success_flag argument should be either AU_PRS_SUCCESS (if the event
 * is a "success" event) or AU_PRS_FAILURE.
 */
static int is_audited_event(au_event_t event, int success_flag) {
  int preselected, read_flag, res;
  au_mask_t mask;

  if (session.user == NULL) {
    char na_buf[512];

    /* Get the non-attributable audit events for the daemon */
    PRIVS_ROOT
    res = getacna(na_buf, sizeof(na_buf));
    PRIVS_RELINQUISH

    if (res == 0) {
      if (getauditflagsbin(na_buf, &mask) < 0) {
        (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
          "error converting non-attributable events: %s", strerror(errno));
        return 0;
      }

    } else {
      switch (res) {
        case -3:
          (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
            "buffer size (%lu) too small for getacna() call",
            (unsigned long) sizeof(na_buf));
          return 0;

        case -2:
          (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
            "error retrieving non-attributable events: %s",
            strerror(errno));
          return 0;

        default:
          (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
            "unknown getacna() error (%d)", res);
          return 0;
      }
    }

  } else {
    PRIVS_ROOT
    res = au_user_mask(session.user, &mask);
    PRIVS_RELINQUISH

    if (res < 0) {
      /* If the user was not authenticated via mod_auth_unix (i.e. the
       * user is a virtual, non-/etc/passwd defined user), don't worry
       * about this error.
       */
      if (session.auth_mech == NULL ||
          strcmp(session.auth_mech, "mod_auth_unix.c") == 0) {
        (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
          "error obtaining audit info for user '%s': %s", session.user,
          strerror(errno));
        return 0;
      }
    }
  }

#ifdef AU_PRS_USECACHE
  /* Using the cached database will be useful once the process is chrooted. */
  read_flag = AU_PRS_USECACHE;
#else
  read_flag = AU_PRS_REREAD;
#endif

  PRIVS_ROOT
  preselected = au_preselect(event, &mask, success_flag, read_flag);
  PRIVS_RELINQUISH

  return preselected;
}

/*
 * Events from bsm/audit_uevents.h:
 *
 *  AUE_login
 *  AUE_logout
 *  AUE_ftpd
 *  AUE_ftpd_logout
 */

static void write_audit_record(audit_event_e event_type, const char *msg,
    au_event_t event) {
  int auditd;
  int res, success_flag;
  pid_t pid;
  uid_t uid;
  token_t *token;

  pid = session.pid ? session.pid : getpid();
  uid = getuid();

  success_flag = get_event_success_flag(event_type);

  res = is_audited_event(event, success_flag);
  if (res == 0) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "event '%s' not audited for user '%s', ignoring",
      get_event_name(event_type), session.user);
    return;

  } else if (res == -1) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error determining whether event '%s' is audited for user '%s': %s",
      get_event_name(event_type), session.user, strerror(errno));
    return;
  }

  PRIVS_ROOT
  auditd = au_open();
  if (auditd < 0) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error opening audit descriptor: %s", strerror(errno));
    PRIVS_RELINQUISH
    return;
  }

  /* Relinquish root privs here, so that the subject credentials in the
   * logs reflect the proper identity of this session process.
   */
  PRIVS_RELINQUISH

#if defined(HAVE_AU_TO_SUBJECT_EX) && defined(HAVE_SETAUDIT_ADDR)
  token = au_to_subject_ex(uid, geteuid(), getegid(), uid, getgid(), pid, pid,
    &audit_tid);
#else
  token = au_to_subject(uid, geteuid(), getegid(), uid, getgid(), pid, pid,
    &audit_tid);
#endif /* !HAVE_AU_TO_SUBJECT_EX */

  PRIVS_ROOT

  if (token == NULL) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error creating subject token: %s", strerror(errno));
    au_close(auditd, AU_TO_NO_WRITE, event);

    PRIVS_RELINQUISH
    return;
  }

  while (au_write(auditd, token) < 0) {
    if (errno == EAGAIN ||
        errno == EINTR) {
      pr_signals_handle();
      continue;
    }
  }
  au_free_token(token);

  token = au_to_text(get_event_text(event_type));
  if (token == NULL) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error creating text token: %s", strerror(errno));
    au_close(auditd, AU_TO_NO_WRITE, event);

    PRIVS_RELINQUISH
    return;
  }

  while (au_write(auditd, token) < 0) {
    if (errno == EAGAIN ||
        errno == EINTR) {
      pr_signals_handle();
      continue;
    }
  }
  au_free_token(token);

#ifdef HAVE_AU_TO_RETURN32
  token = au_to_return32(get_event_errno(event_type),
    (int32_t) success_flag == AU_PRS_SUCCESS ? 0 : -1);
#else
  token = au_to_return(get_event_errno(event_type),
    (unsigned int) success_flag == AU_PRS_SUCCESS ? 0 : -1);
#endif /* !HAVE_AU_TO_RETURN32 */
  if (token == NULL) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error creating return value token: %s", strerror(errno));
    au_close(auditd, AU_TO_NO_WRITE, event);

    PRIVS_RELINQUISH
    return;
  }

  while (au_write(auditd, token) < 0) {
    if (errno == EAGAIN ||
        errno == EINTR) {
      pr_signals_handle();
      continue;
    }
  }
  au_free_token(token);

  if (au_close(auditd, AU_TO_WRITE, event) < 0) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error writing '%s' audit record: %s", msg, strerror(errno));
  }

  PRIVS_RELINQUISH
  return;
}

static void set_audit_info(void) {
  int res;
  au_mask_t mask;
#ifdef HAVE_SETAUDIT_ADDR
  auditinfo_addr_t audit_info;
#else
  auditinfo_t audit_info;
#endif /* !HAVE_SETAUDIT_ADDR */

  audit_info.ai_auid = -1;
  audit_info.ai_asid = session.pid ? session.pid : getpid();

  mask.am_success = mask.am_failure = 0;

  PRIVS_ROOT
  res = au_user_mask(session.user, &mask);
  if (res < 0) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error obtaining audit info for user '%s': %s", session.user,
      strerror(errno));

    PRIVS_RELINQUISH
    return;
  }

  audit_info.ai_mask.am_success = mask.am_success;
  audit_info.ai_mask.am_failure = mask.am_failure;

  audit_info.ai_termid = audit_tid;

#ifdef HAVE_SETAUDIT_ADDR
  res = setaudit_addr(&audit_info, sizeof(audit_info));
#else
  res = setaudit(&audit_info);
#endif /* !HAVE_SETAUDIT_ADDR */

  if (res < 0) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error setting audit info: %s", strerror(errno));
  }

  PRIVS_RELINQUISH
}

/* Configuration directive handlers
 */

/* usage: AuditEngine on|off */
MODRET set_auditengine(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: AuditEventID number */
MODRET set_auditeventid(cmd_rec *cmd) {
  config_rec *c;
  char *ptr = NULL;
  unsigned long event_id;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  event_id = strtol(cmd->argv[1], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1],
      "' is not a number", NULL));
  }

  if (event_id < 36865 ||
      event_id > 65535) {
    CONF_ERROR(cmd, "must be between 36865 and 65535");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = event_id;

  return PR_HANDLED(cmd);
}

/* usage: AuditLog "none"|path */
MODRET set_auditlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET audit_post_pass(cmd_rec *cmd) {
  int res;

  if (!audit_engine) {
    return PR_DECLINED(cmd);
  }

  set_audit_info();

  PRIVS_ROOT
  res = setauid(&session.uid);
  PRIVS_RELINQUISH

  if (res < 0) {
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "error setting audit ID %lu: %s", (unsigned long) session.uid,
      strerror(errno));
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void audit_authenticationcode_ev(const void *event_data,
    void *user_data) {
  int auth_code = *((int *) event_data);
  audit_event_e event_type;

  switch (auth_code) { 
    case PR_AUTH_OK_NO_PASS:
      event_type = PR_AUDIT_EVENT_AUTH_OK_NO_PASS;
      break;

    case PR_AUTH_RFC2228_OK:
      event_type = PR_AUDIT_EVENT_AUTH_RFC2228_OK;
      break;

    case PR_AUTH_OK:
      event_type = PR_AUDIT_EVENT_AUTH_OK;
      break;

    case PR_AUTH_ERROR:
      event_type = PR_AUDIT_EVENT_AUTH_ERROR;
      break;

    case PR_AUTH_NOPWD:
      event_type = PR_AUDIT_EVENT_AUTH_NOPWD;
      break;

    case PR_AUTH_BADPWD:
      event_type = PR_AUDIT_EVENT_AUTH_BADPWD;
      break;

    case PR_AUTH_AGEPWD:
      event_type = PR_AUDIT_EVENT_AUTH_AGEPWD;
      break;

    case PR_AUTH_DISABLEDPWD:
      event_type = PR_AUDIT_EVENT_AUTH_DISABLEDPWD;
      break;

    default:
      (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
        "unknown authenication code %d", auth_code);
      return;
  }

  write_audit_record(event_type, get_event_text(event_type), audit_event_id);
}

static void audit_exit_ev(const void *event_data, void *user_data) {
#ifdef AUE_ftpd_logout
  write_audit_record(PR_AUDIT_EVENT_CONNECTION_CLOSE, "CONNECTION_CLOSED",
    AUE_ftpd_logout);
#else
  write_audit_record(PR_AUDIT_EVENT_CONNECTION_CLOSE, "CONNECTION_CLOSED",
    AUE_logout);
#endif /* !AUE_ftpd_logout */
}

static void audit_maxloginattempts_ev(const void *event, void *user_data) {
  write_audit_record(PR_AUDIT_EVENT_EXCEEDED_MAX_LOGIN_ATTEMPTS,
    "EXCEEDED_MAX_LOGIN_ATTEMPTS", audit_event_id);
}

#if defined(PR_SHARED_MODULE)
static void audit_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_audit.c", (const char *) event_data) == 0) {
    pr_log_debug(DEBUG0, MOD_AUDIT_VERSION ": module unloaded");
    pr_event_unregister(&audit_module, NULL, NULL);
  }
}
#endif /* !PR_SHARED_MODULE */

static void audit_rootlogin_ev(const void *event, void *user_data) {
  write_audit_record(PR_AUDIT_EVENT_ROOT_LOGIN_DENIED, "ROOT_LOGIN_DENIED",
    audit_event_id);
}

/* Initialization functions
 */

static int audit_sess_init(void) {
  config_rec *c;
  int au_family;

  if (cannot_audit(0)) {
    audit_engine = FALSE;
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuditEngine", FALSE);
  if (c) {
    audit_engine = *((int *) c->argv[0]);
  }

  if (!audit_engine)
    return 0;

  c = find_config(main_server->conf, CONF_PARAM, "AuditLog", FALSE);
  if (c) {
    const char *path = c->argv[0];

    if (strcasecmp(path, "none") != 0) {
      int res;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &audit_logfd, 0640);
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_AUDIT_VERSION
            ": notice: unable to open AuditLog '%s': %s", path,
            strerror(errno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_NOTICE, MOD_AUDIT_VERSION
            ": notice: unable to open AuditLog '%s': "
            "Parent directory is world writable", path);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_NOTICE, MOD_AUDIT_VERSION
            ": notice: unable to open AuditLog '%s': "
            "Cannot log to a symbolic link", path);
        }
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuditEventID", FALSE);
  if (c) {
    audit_event_id = *((unsigned long *) c->argv[0]);
    (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
      "now using event ID %lu instead of %lu", (unsigned long) audit_event_id,
      (unsigned long) AUE_ftpd);
  }

  pr_event_register(&audit_module, "core.exit", audit_exit_ev, NULL);
  pr_event_register(&audit_module, "mod_auth.authentication-code",
    audit_authenticationcode_ev, NULL);
  pr_event_register(&audit_module, "mod_auth.max-login-attempts",
    audit_maxloginattempts_ev, NULL);
  pr_event_register(&audit_module, "mod_auth.root-login",
    audit_rootlogin_ev, NULL);

#ifdef PR_USE_IPV6
  if (pr_netaddr_use_ipv6()) {
    int family = pr_netaddr_get_family(session.c->remote_addr);

    switch (family) {
      case AF_INET:
        au_family = AU_IPv4;
        break;

# ifdef AU_IPv6
      case AF_INET6:
        au_family = AU_IPv6;
        break;
# endif

      default:
        (void) pr_log_writefile(audit_logfd, MOD_AUDIT_VERSION,
          "unknown address family for %s (%d), using AF_INET",
          pr_netaddr_get_ipstr(session.c->remote_addr), family);
        au_family = AU_IPv4;
    }

  } else {
    au_family = AU_IPv4;
  }
#else
  au_family = AU_IPv4;
#endif /* PR_USE_IPV6 */

#ifdef HAVE_SETAUDIT_ADDR
  audit_tid.at_port = (dev_t) pr_netaddr_get_port(session.c->remote_addr);
  audit_tid.at_type = au_family;
  memcpy(&(audit_tid.at_addr[0]),
    pr_netaddr_get_inaddr(session.c->remote_addr),
    pr_netaddr_get_inaddr_len(session.c->remote_addr));
#else
  audit_tid.port = (dev_t) pr_netaddr_get_port(session.c->remote_addr);

  /* Just use inet_addr(3) here; it's easier. */
  audit_tid.machine = inet_addr(pr_netaddr_get_ipstr(session.c->remote_addr));
#endif /* !HAVE_SETAUDIT_ADDR */

  return 0;
}

static int audit_init(void) {

#if defined(PR_SHARED_MODULE)
  pr_event_register(&audit_module, "core.module-unload", audit_mod_unload_ev,
    NULL);
#endif /* !PR_SHARED_MODULE */

  return 0;
}

/* Module API tables
 */

static conftable audit_conftab[] = {
  { "AuditEngine",	set_auditengine,	NULL },
  { "AuditEventID",	set_auditeventid,	NULL },
  { "AuditLog",		set_auditlog,		NULL },

  { NULL, NULL, NULL }
};

static cmdtable audit_cmdtab[] = {
  { POST_CMD,	C_PASS,	G_NONE,	audit_post_pass,	FALSE, FALSE },
  { 0, NULL }
};

module audit_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "audit",

  /* Module config handler table */
  audit_conftab,

  /* Module command handler table */
  audit_cmdtab,

  /* Module auth handler table */
  NULL,

  /* Module init function */
  audit_init,

  /* Session init function */
  audit_sess_init,

  /* Module version */
  MOD_AUDIT_VERSION
};
