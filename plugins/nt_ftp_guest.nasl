#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10166);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2017/03/03 22:22:41 $");

  script_cve_id("CVE-1999-0546");
  script_bugtraq_id(87877);
  script_osvdb_id(129);
 
  script_name(english:"Windows NT FTP 'guest' Account Present");
  script_summary(english:"Checks for guest/guest.");

  script_set_attribute(attribute:"synopsis", value:
"There is a 'guest' account on the remote FTP server.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a 'guest' FTP account enabled. This could
allow a remote attacker to upload or download arbitrary files on the
remote host.

Note that this plugin only tests for guest accounts over FTP.");
  script_set_attribute(attribute:"solution", value:
"Disable this FTP account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"1995/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");

  script_dependencies(
    "ftpserver_detect_type_nd_version.nasl",
    "ftp_anonymous.nasl",
    "DDI_FTP_Any_User_Login.nasl",
    "os_fingerprint.nasl"
  );
  script_require_ports("Services/ftp", 21);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

#
# The script code starts here
#

include('audit.inc');
include('global_settings.inc');
include('ftp_func.inc');

os = get_kb_item("Host/OS");
if ("Windows" >!< os) audit(AUDIT_OS_NOT, "Windows");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);
if (get_kb_item("ftp/"+port+"/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

# MA 2008-08-23: we used to test "guest"/"" but the summary says that we test 
# guest/guest. Just in case, I added both cases

foreach pass (make_list("", "guest"))
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  if (ftp_authenticate(socket:soc, user:"guest", pass: pass))
  {
    login = get_kb_item("ftp/login");
    if(!login)
    {
     replace_kb_item(name:"ftp/login", value: "guest");
     replace_kb_item(name:"ftp/password", value: pass);
    }
    if (pass != "")
      rep = pass;
    else
      rep = 'The guest account has no password';

    if (report_verbosity > 0)
    {
      report = '\nNessus was able to gain access using the following set of ' +
        'credentials :\n' +
        '\n' +
        '  Username : guest\n' +
        '  Password : ' + rep + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    close(soc);
    exit(0);
  }
  close(soc);
}
audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
