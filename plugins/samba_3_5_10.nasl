#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55733);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id("CVE-2011-2522", "CVE-2011-2694");
  script_bugtraq_id(48899, 48901);
  script_osvdb_id(74071, 74072);
  script_xref(name:"EDB-ID", value:"17577");
  script_xref(name:"Secunia", value:"45393");

  script_name(english:"Samba 3.x < 3.3.16 / 3.4.14 / 3.5.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba 3.x running on the
remote host is earlier than 3.3.16 / 3.4.14 / 3.5.10. As such, it is
potentially affected by several vulnerabilities in the Samba Web
Administration Tool (SWAT) :

  - A cross-site scripting vulnerability exists because of a
    failure to sanitize input to the username parameter of
    the 'passwd' program. (Issue #8289)

  - A cross-site request forgery (CSRF) vulnerability can
    allow SWAT to be manipulated when a user who is logged
    in as root is tricked into clicking specially crafted
    URLs sent by an attacker. (Issue #8290)

Note that these issues are only exploitable when SWAT it enabled, and
it is not enabled by default.

Also note that Nessus has relied only on the self-reported version
number and has not actually determined whether SWAT is enabled, tried
to exploit these issues, or determine if the associated patches have
been applied.");
  script_set_attribute(attribute:"solution", value:
"Either apply one of the patches referenced in the project's advisory
or upgrade to 3.3.16 / 3.4.14 / 3.5.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=8289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=8290");
  script_set_attribute(attribute:"see_also", value:"http://samba.org/samba/security/CVE-2011-2522");
  script_set_attribute(attribute:"see_also", value:"http://samba.org/samba/security/CVE-2011-2694");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.3.16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.4.14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.5.10.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");

lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba" >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba.");
if ("Samba 3" >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba 3.x.");

version = lanman - 'Samba ';
if (version =~ "^3(\.[345])?$")
  exit(1, "The Samba version, "+version+" is not granular enough to make a determination.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 3 && ver[1] < 3) ||
  (ver[0] == 3 && ver[1] == 3 && ver[2] < 16) ||
  (ver[0] == 3 && ver[1] == 4 && ver[2] < 14) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 10)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 3.3.16 / 3.4.14 / 3.5.10\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'Samba version '+version+' is listening on port '+port+' and not affected.');
