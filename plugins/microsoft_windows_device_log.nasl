#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92363);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Windows Device Logs");
  script_summary(english:"Collect device logs from the machine.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect available device logs from the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect available device logs from the remote
Windows host and add them as attachments.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Incident Response");
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

exit(0, "This plugin is temporarily disabled");


port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"ADMIN$");

if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"ADMIN$");
}

# Vista and later
logfiles = make_list('\\inf\\setupapi.dev.log', '\\inf\\setupapi.app.log', '\\inf\\setupapi.offline.log', '\\inf\\setupapi.setup.log');
attachments = make_list();
count = 0;
log_content = '';
foreach logfile(logfiles)
{
  fh = CreateFile(
      file               : logfile,
      desired_access     : GENERIC_READ,
      file_attributes    : FILE_ATTRIBUTE_NORMAL,
      share_mode         : FILE_SHARE_READ,
      create_disposition : OPEN_EXISTING
  );
  if (isnull(fh))
  {
    continue;
  }

  off = 0;
  repeat
  {
    data = ReadFile(handle:fh, length:4096, offset:off);
    log_content += data;
    len = strlen(data);
    off += len;
  }
  until (len < 4096 || off > 100*1024*1024); # limit to 100 MB
  CloseFile(handle:fh);

  attachments[count] = make_array();
  attachments[count]["name"] = ereg_replace(string:logfile, pattern:"^(?:.+\\)?(.+)$", replace:"\1");
  attachments[count]["value"] = log_content;
  attachments[count]["type"] = "text/plain";
  count++;
  log_content = '';
}

NetUseDel();

if (max_index(attachments) > 0)
{
  report = 'Device logs attached.';
  security_report_with_attachments(port:0, level:0, extra:report, attachments:attachments);
}
