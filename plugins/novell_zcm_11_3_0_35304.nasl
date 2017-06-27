#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72814);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/07 15:36:47 $");

  script_cve_id("CVE-2013-3706");
  script_bugtraq_id(65912);
  script_osvdb_id(104002);
  script_xref(name:"TRA", value:"TRA-2014-02");

  script_name(english:"Novell ZENworks Configuration Management < 11.3.0.35304 PreBoot Service Directory Traversal");
  script_summary(english:"Checks ZENworks version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote host is affected by a directory traversal
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Novell ZENworks Configuration
Management installed prior to 11 SP3 (11.3.0.35304).  It is, therefore,
affected by a directory traversal vulnerability due to improper
validation of an unspecified parameter of the PreBoot Service when
reading files.  A remote, unauthenticated attacker may be able to read
arbitrary files."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2014-02");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-055/");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7014663");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7014213");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell ZENworks SP3 (11.3.0.35304) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_detect.nasl");
  script_require_keys("SMB/Novell/ZENworks/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Novell/ZENworks/Installed");

app = "Novell ZENworks Configuration Management";

path  = get_kb_item_or_exit("SMB/Novell/ZENworks/Path");
version = get_kb_item_or_exit("SMB/Novell/ZENworks/Version");

fix = "11.3.0.35304";

if (version =~ "^11\.[23]([^0-9]|$)" && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
 port = get_kb_item('SMB/transport');
 if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11 SP3 (' + fix + ')' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
