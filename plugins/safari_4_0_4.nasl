#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42478);
  script_version("$Revision: 1.15 $");

  script_cve_id(
    "CVE-2009-2804",
    "CVE-2009-2414",
    "CVE-2009-2416",
    "CVE-2009-2816",
    "CVE-2009-2842",
    "CVE-2009-3384"
  );
  script_bugtraq_id(36357, 36994, 36995, 36997);
  script_osvdb_id(56985, 56990, 57949, 59940, 59942, 59943, 59944);

  script_name(english:"Safari < 4.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Safari installed on the remote Windows host is earlier
than 4.0.4.  Such versions are potentially affected by several 
issues :

  - An integer overflow in the handling of images with an
    embedded color profile could lead to a crash or 
    arbitrary code execution. (CVE-2009-2804)

  - Multiple use-after-free issues exist in libxml2, the
    most serious of which could lead to a program crash.
    (CVE-2009-2414, CVE-2009-2416)

  - An issue in the handling of navigations initiated via 
    the 'Open Image in New Tab', 'Open Image in New Window'
    or 'Open Link in New Tab' shortcut menu options could
    be exploited to load a local HTML file, leading to
    disclosure of sensitive information. (CVE-2009-2842)

  - An issue involving WebKit's inclusion of custom HTTP
    headers specified by a requesting page in preflight
    requests in support of Cross-Origin Resource Sharing
    can facilitate cross-site request forgery attacks. 
    (CVE-2009-2816)

  - Multiple issues in WebKit's handling of FTP directory 
    listings may lead to information disclosure, unexpected
    application termination, or execution of arbitrary 
    code. (CVE-2009-3384)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3949"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Nov/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/18277"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 4.0.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 352, 399);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/11/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/11/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/12"
  );
 script_cvs_date("$Date: 2016/12/14 20:22:11 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");


path = get_kb_item("SMB/Safari/Path");
version = get_kb_item("SMB/Safari/FileVersion");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 5 ||
  (
    ver[0] == 5 &&
    (
      ver[1] < 31 ||
      (
        ver[1] == 31 && 
        (
          ver[2] < 21 ||
          (ver[2] == 21 && ver[3] < 10)
        )
      )
    )
  )
)
{
  if (report_verbosity > 0)
  {
    if (isnull(path)) path = "n/a";

    prod_version = get_kb_item("SMB/Safari/ProductVersion");
    if (!isnull(prod_version)) version = prod_version;

    report = string(
      "\n",
      "Nessus collected the following information about the current install\n",
      "of Safari on the remote host :\n",
      "\n",
      "  Version : ", version, "\n",
      "  Path    : ", path, "\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
