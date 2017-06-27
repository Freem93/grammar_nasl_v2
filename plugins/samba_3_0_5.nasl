#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17720);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id("CVE-2004-0600");
  script_bugtraq_id(10780);
  script_osvdb_id(8190);
  script_xref(name:"EDB-ID", value:"364");

  script_name(english:"Samba SWAT 3.0.2 - 3.0.4 HTTP Basic Auth base64 Buffer Overflow");
  script_summary(english:"Checks version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is between 3.0.2 and 3.0.4, inclusive.  An error exists in the
base64 decoding functions, which can result in a buffer overflow.");

  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.0.5.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2004-0600.html");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl", "swat_detect.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report Paranoia' is set to 'Paranoid'.");

if (!get_kb_item("Settings/PCI_DSS"))
{
  ports = get_kb_list("SWAT/*");
  if (isnull(ports) || max_index(ports) == 0)
    exit(0, "SWAT does not appear to be listening on the remote host.");
}

port = get_kb_item_or_exit("SMB/transport");
lanman = get_kb_item_or_exit("SMB/NativeLanManager");

# Ensure the remote server is running Samba 3.0.x.
if ("Samba " >!< lanman)
  exit(0, "The SMB service listening on port "+port+" is not running Samba.");

# Split and convert third version number to integer.
version = lanman - "Samba ";
ver = split(version, sep:".", keep:FALSE);
ver[2] = int(ver[2]);

if (ver[0] == 3 && ver[1] == 0 && (ver[2] >= 2 && ver[2] <= 4))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.0.5' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Samba "+version+" install listening on port "+port+" is not affected.");
