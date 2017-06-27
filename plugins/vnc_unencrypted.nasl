#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(65792);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2014/03/12 10:53:57 $");

 script_name(english:"VNC Server Unencrypted Communication Detection");
 script_summary(english:"Identifies the RFB protocol version (VNC) & security types");

 script_set_attribute(attribute:"synopsis", value:
"A VNC server with one or more unencrypted 'security-types' is running
on the remote host.");
 script_set_attribute(attribute:"description", value:
"This script checks the remote VNC server protocol version and the
available 'security types' to determine if any unencrypted
'security-types' are in use or available.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("vnc_security_types.nasl");
 script_require_ports("Services/vnc", 5900);
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

# Security types names
rfb_sec = make_array(
  -6, "MS Logon (UltraVNC)",
 0, "Invalid (connection refused)",
 1, "None",
 2, "VNC authentication",
 5, "RA2",
 6, "RA2ne",
 16, "Tight",
 17, "Ultra",
 18, "TLS",
 19, "VeNCrypt",
 20, "GTK-VNC SASL",
 21, "MD5 hash authentication",
 22, "Colin Dean xvp",
 30, "Mac OSX SecType 30",
 35, "Mac OSX SecType 35"
);

port = get_service(svc:'vnc', exit_on_fail:TRUE);
types = get_kb_list_or_exit('VNC/SecurityType/' + port);

report = "";
report_none = "";
report_question = "";

foreach st (types)
{
  # these security types do not encrypt all data communications
  if ( (st == "1") ||
       (st == "2") ||
       (st == "6") ||
       (st == "16") ||
       (st == "21") ||
       (st == "22")
     )
  {
    report_none = strcat(report_none, '  ', st, ' (', rfb_sec[st], ')\n');
  }

  # these security types can encrypt all data communications but do not by default
  if ( (st == "6") ||
       (st == "17") ||
       (st == "20") ||
       (st == "30") ||
       (st == "35")
     )
  {
    report_question = strcat(report_question, '  ', st, ' (', rfb_sec[st], ')\n');
  }
}

if (report_none)
{
  if (max_index(split(report_question)) > 1)
  {
    s = "s";
    es = "";
  }
  else
  {
    s = "";
    es = "es";
  }

  report = string (
    "\n",
    "The remote VNC server supports the following security type", s, "\n",
    "which do", es, " not perform full data communication encryption :\n",
   "\n",
    report_none
  );
}

if (report_question)
{
  if (max_index(split(report_question)) > 1)
  {
    s = "s";
    es = "";
  }
  else
  {
    s = "";
    es = "es";
  }

  report = string (
    report,
    "\n",
    "The remote VNC server supports the following security type", s, "\n",
    "which do", es, " not perform full data communication encryption by", "\n",
    "default and thus should be checked to ensure that full data", "\n",
    "encryption is enabled :\n",
    "\n",
    report_question
  );
}

if (report)
{
  if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
  if (report_verbosity > 0) security_note(port:port, extra:report);
  else security_note(port);
  exit(0);
}
else exit(0, "No unencrypted VNC security types were identified.");
