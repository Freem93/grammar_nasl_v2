#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83353);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2015-1670",
    "CVE-2015-1671",
    "CVE-2015-1715"
  );
  script_bugtraq_id(
    74485,
    74490,
    74503
  );
  script_osvdb_id(
    121997,
    121998,
    122010
  );
  script_xref(name:"MSFT", value:"MS15-049");
  script_xref(name:"MSFT", value:"MS15-044");

  script_name(english:"Microsoft Silverlight < 5.1.40416.00 Multiple Vulnerabilities (MS15-044 / MS15-049) (Mac OS X)");
  script_summary(english:"Checks the version of Microsoft Silverlight.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application framework installed on the remote Mac OS X
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Silverlight installed on the remote host is
affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to
    improper handling of OpenType fonts by the Windows
    DirectWrite library. A remote attacker can exploit this
    vulnerability by convincing a user to open a file or
    visit a website containing a specially crafted OpenType
    font, resulting in the disclosure of sensitive
    information. (MS15-044 / CVE-2015-1670)

  - A remote code execution vulnerability exists due to
    improper handling of TrueType font files by the Windows
    DirectWrite library. A remote attacker can exploit this
    vulnerability by convincing a user to open a specially
    crafted document or visit a website containing a
    specially crafted TrueType font file, resulting in
    execution of arbitrary code in the context of the
    current user. (MS15-044 / CVE-2015-1671)

  - A flaw exists in Microsoft Silverlight that allows a
    remote attacker, via a specially crafted Silverlight
    application, to execute arbitrary code with the same or
    higher level of permissions as the currently logged on
    user. (MS15-049 / CVE-2015-1715)");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms15-049");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms15-044");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_silverlight_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Silverlight/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Silverlight";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);


bulletin = "MS15-049";
kb = "3056819";

fixed_version = "5.1.40416.00";
if (version =~ "^5\." && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  if (defined_func("report_xml_tag")) report_xml_tag(tag:bulletin, value:kb);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' +fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The Microsoft Silverlight "+version+" install is not reported to be affected.");
