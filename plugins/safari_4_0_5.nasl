#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45045);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id(
    "CVE-2009-2285",
    "CVE-2010-0040",
    "CVE-2010-0041",
    "CVE-2010-0042",
    "CVE-2010-0043",
    "CVE-2010-0044",
    "CVE-2010-0045",
    "CVE-2010-0046",
    "CVE-2010-0047",
    "CVE-2010-0048",
    "CVE-2010-0049",
    "CVE-2010-0050",
    "CVE-2010-0051",
    "CVE-2010-0052",
    "CVE-2010-0053",
    "CVE-2010-0054"
  );
  script_bugtraq_id(
    35451,
    38673,
    38674,
    38675,
    38676,
    38677,
    38683,
    38684,
    38685,
    38686,
    38687,
    38688,
    38689,
    38690,
    38691,
    38692
  );
  script_osvdb_id(
    55265,
    62307,
    62933,
    62934,
    62935,
    62936,
    62937,
    62938,
    62939,
    62940,
    62941,
    62942,
    62943,
    62947,
    62948,
    62949
  );

  script_name(english:"Safari < 4.0.5 Multiple Vulnerabilities");
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
than 4.0.5.  It thus is potentially affected by several issues :

  - A buffer underflow in ImageIO's handling of TIFF images
    could lead to a crash or arbitrary code execution.
    (CVE-2009-2285)

  - An integer overflow in the handling of images with an
    embedded color profile could lead to a crash or
    arbitrary code execution. (CVE-2010-0040)

  - An uninitialized memory access issue in ImageIO's
    handling of BMP images could result in sending of data
    from Safari's memory to a website. (CVE-2010-0041)

  - An uninitialized memory access issue in ImageIO's
    handling of TIFF images could result in the sending of
    data from Safari's memory to a website. (CVE-2010-0042)

  - A memory corruption issue in the handling of TIFF
    images could lead to a crash or arbitrary code
    execution. (CVE-2010-0043)

  - An implementation issue in the handling of cookies set
    by RSS and Atom feeds could result in a cookie being
    set when visiting or updating a feed even if Safari is
    configured to block cookies via the 'Accept Cookies'
    preference. (CVE-2010-0044)

  - An issue in Safari's handling of external URL schemes
    could cause a local file to be opened in response to a
    URL encountered on a web page, which could allow a
    malicious web server to execute arbitrary code.
    (CVE-2010-0045)

  - A memory corruption issue in WebKit's handling of CSS
    format() arguments could lead to a crash or arbitrary
    code execution. (CVE-2010-0046)

  - A use-after-free issue in the handling of HTML object
    element fallback content could lead to a crash or
    arbitrary code execution. (CVE-2010-0047)

  - A use-after-free issue in WebKit's parsing of XML
    documents could lead to a crash or arbitrary code
    execution. (CVE-2010-0048)

  - A use-after-free issue in the handling of HTML elements
    containing right-to-left displayed text could lead to a
    crash or arbitrary code execution. (CVE-2010-0049)

  - A use-after-free issue in WebKit's handling of
    incorrectly nested HTML tags could lead to a crash or
    arbitrary code execution. (CVE-2010-0050)

  - An implementation issue in WebKit's handling of cross-
    origin stylesheet requests when visiting a malicious
    website could result in disclosure of the content of
    protected resources on another website. (CVE-2010-0051)

  - A use-after-free issue in WebKit's handling of
    callbacks for HTML elements could lead to a crash or
    arbitrary code execution. (CVE-2010-0052)

  - A use-after-free issue in the rendering of content with
    a CSS display property set to 'run-in' could lead to a
    crash or arbitrary code execution. (CVE-2010-0053)

  - A use-after-free issue in WebKit's handling of HTML
    image elements could lead to a crash or arbitrary code
    execution. (CVE-2010-0054)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4070");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/19255");
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 4.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");


path = get_kb_item("SMB/Safari/Path");
version = get_kb_item("SMB/Safari/FileVersion");
if (isnull(version)) exit(1, "The 'SMB/Safari/FileVersion' KB item is missing.");

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
          ver[2] < 22 ||
          (ver[2] == 22 && ver[3] < 7)
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

    report = '\n' +
      'Nessus collected the following information about the current install\n' +
      'of Safari on the remote host :\n' +
      '\n' +
      '  Version : ' + version + '\n' +
      '  Path    : ' + path + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
