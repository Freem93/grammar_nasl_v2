#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64459);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/16 14:58:25 $");

  script_cve_id("CVE-2013-0213", "CVE-2013-0214");
  script_bugtraq_id(57631);
  script_osvdb_id(89626, 89627);

  script_name(english:"Samba < 3.5.21 / 3.6.12 / 4.0.2 SWAT Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 3.5.x prior to 3.5.21, 3.6.x prior to 3.6.12, or 4.x prior to 
4.0.1. It is, therefore, affected by the following vulnerabilities :

  - An unspecified flaw exists in the Samba Web
    Administration Tool (SWAT) that allows a remote attacker
    to conduct clickjacking attacks via a FRAME or IFRAME
    element. (CVE-2013-0213)

  - A cross-site request forgery vulnerability exists due to
    a failure to require multiple steps or explicit
    confirmation for sensitive transactions in the Samba
    Web Administration Tool (SWAT). A remote attacker can
    exploit this, by convincing a user to follow a crafted
    URL, to cause the user to perform unintended actions.
    (CVE-2013-0213)

Note that these vulnerabilities are only exploitable when SWAT is
enabled, and it is not enabled by default. Additionally, note that
Nessus has not tested for these issues but has instead relied only on
the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-0213.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-0214.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.5.21 / 3.6.12 / 4.0.2 or later.
Alternatively, install the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("SMB/transport");
lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (lanman =~ '^Samba (3(\\.[56])?|4(\\.0)?)$') exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 3 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] < 21) ||
      (ver[1] == 6 && ver[2] < 12)
    )
  ) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 2)
)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version + 
             '\n  Fixed version      : 3.5.21 / 3.6.12 / 4.0.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
