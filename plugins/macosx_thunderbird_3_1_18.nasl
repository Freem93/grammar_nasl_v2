#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57776);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2011-3659",
    "CVE-2011-3670",
    "CVE-2012-0442",
    "CVE-2012-0444",
    "CVE-2012-0449"
  );
  script_bugtraq_id(
    51753,
    51754,
    51755,
    51756,
    51786
  );
  script_osvdb_id(78733, 78734, 78736, 78739, 78740, 78774);

  script_name(english:"Thunderbird 3.1 < 3.1.18 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an email client that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.18. 
Such versions are potentially affected by multiple vulnerabilities :

  - A use-after-free error exists related to removed
    nsDOMAttribute child nodes.(CVE-2011-3659)

  - The IPv6 literal syntax in web addresses is not being
    properly enforced. (CVE-2011-3670)

  - Various memory safety issues exist. (CVE-2012-0442)

  - Memory corruption errors exist related to the
    decoding of Ogg Vorbis files and processing of
    malformed XSLT stylesheets. (CVE-2012-0444,
    CVE-2012-0449)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc3986.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-07.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-08.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
# nb: make sure we have at least 3 parts for the check.
for (i=max_index(ver); i<3; i++)
  ver[i] = 0;

if (ver[0] == 3 && ver[1] == 1 && ver[2] < 18)
{
  if (report_verbosity > 0)
  {
    info +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.1.18' + '\n';
    security_hole(port:0, extra:info);
  }
  else security_hole(0);
  exit(0);
}
else 
{
  if (ver[0] == 3 && ver[1] == 1) exit(0, "The Thunderbird "+version+" install is not affected.");
  else exit(0, "Thunderbird 3.1.x is not installed.");
}
