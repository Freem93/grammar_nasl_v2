#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86905);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2015-3968");
  script_bugtraq_id(77291);
  script_osvdb_id(129347);
  script_xref(name:"ICSA", value:"15-265-03");

  script_name(english:"Janitza Hard-Coded FTP Password");
  script_summary(english:"Checks if FTP login is available via a hard-coded password.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an FTP server that can be accessed with
hard-coded credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Janitza FTP server can be accessed with hard-coded
credentials. A remote attacker can leverage the credentials to upload
and download arbitrary files.");
  script_set_attribute(attribute:"see_also", value:"https://ics-cert.us-cert.gov/advisories/ICSA-15-265-03");
  script_set_attribute(attribute:"see_also", value:"http://www.janitza.com/experimental-downloads.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an experimental firmware version available from the vendor
website. Alternatively, change the administrator FTP password and
secure non-essential ports with a firewall per the vendor
documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:janitza:umg_508");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:janitza:umg_509");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:janitza:umg_511");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:janitza:umg_604");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:janitza:umg_605");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item("ftp/"+port+"/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

res = ftp_authenticate(socket:soc, user:"admin", pass:"Janitza");
ftp_close(socket:soc);

if (res)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  User     : admin\n' +
      '  Password : Janitza\n';
    security_hole(port:port, extra:report);
  }
  else
  {
    security_hole(port);
  }
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
