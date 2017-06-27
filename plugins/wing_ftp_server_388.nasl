#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55652);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_bugtraq_id(48335);
  script_osvdb_id(73206);
  script_xref(name:"Secunia", value:"44993");

  script_name(english:"Wing FTP Server SSH Public Key Authentication Bypass");
  script_summary(english:"Checks version of Wing FTP");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is vulnerable to an authentication bypass
attack.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server is running a version of Wing FTP Server earlier
than 3.8.8.  As such, it is reportedly affected by an authentication
bypass vulnerability when SSH public key authentication is used. 

An attacker can exploit this issue by logging into the FTP server with
a password even though the server is configured to use only public key
authentication.  Successful exploitation of this issue requires
knowledge of valid account credentials. 

Note that public key authentication configuration in Wing FTP is set
on a per-user basis and that Nessus has not verified that this
configuration is in effect for any users.");
  script_set_attribute(attribute:"see_also", value:"http://www.wftpserver.com/serverhistory.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.8.8 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:wftpserver:wing_ftp_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("wing_ftp_server_detect.nasl");
  script_require_keys("SMB/Wing_FTP/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port =  get_kb_item("SMB/transport");
base = get_kb_item_or_exit("SMB/Wing_FTP/Path");

# Check if the version is vulnerable.
fixed = "3.8.8";
version = get_kb_item_or_exit("SMB/Wing_FTP/Version");

if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + base +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n'; 
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
} 
else exit(0, "Wing FTP " + version + " on the remote host is not affected.");
