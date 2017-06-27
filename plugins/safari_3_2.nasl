#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34772);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id(
    "CVE-2005-2096",
    "CVE-2008-1767",
    "CVE-2008-2303",
    "CVE-2008-2317",
    "CVE-2008-2327",
    "CVE-2008-2332",
    "CVE-2008-3608",
    "CVE-2008-3623",
    "CVE-2008-3642",
    "CVE-2008-3644",
    "CVE-2008-4216"
  );
  script_bugtraq_id(14162, 29312, 30832, 32291);
  script_osvdb_id(
    17827,
    45419,
    47289,
    47290,
    47795,
    48180,
    48195,
    48970,
    49939,
    49940,
    49941
  );

  script_name(english:"Safari < 3.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Safari");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
  script_set_attribute(attribute:"description", value:
"The version of Safari installed on the remote Windows host is earlier
than 3.2.  Such versions are potentially affected by several issues :

  - Safari includes a version of zlib that is affected by
    multiple vulnerabilities. (CVE-2005-2096)

  - A heap-based buffer overflow issue in the libxslt library
    could lead to a crash or arbitrary code execution.
    (CVE-2008-1767)

  - A signedness issue in Safari's handling of JavaScript
    array indices could lead to a crash or arbitrary code
    execution. (CVE-2008-2303)

  - A memory corruption issue in WebCore's handling of style
    sheet elements could lead to a crash or arbitrary code
    execution. (CVE-2008-2317)

  - Multiple uninitialized memory access issues in libTIFF's
    handling of LZW-encoded TIFF images could lead to a
    crash or arbitrary code execution. (CVE-2008-2327)

  - A memory corruption issue in ImageIO's handling of TIFF
    images could lead to a crash or arbitrary code
    execution. (CVE-2008-2332).

  - A memory corruption issue in ImageIO's handling of
    embedded ICC profiles in JPEG images could lead to a
    crash or arbitrary code execution. (CVE-2008-3608)

  - A heap-based buffer overflow in CoreGraphics' handling
    of color spaces could lead to a crash or arbitrary code
    execution. (CVE-2008-3623)

  - A buffer overflow in the handling of images with an
    embedded ICC profile could lead to a crash or arbitrary
    code execution. (CVE-2008-3642)

  - Disabling autocomplete on a form field may not prevent
    the data in the field from being stored in the browser
    page cache. (CVE-2008-3644)

  - WebKit's plug-in interface does not block plug-ins from
    launching local URLs, which could allow a remote
    attacker to launch local files in Safari and lead to the
    disclosure of sensitive information. (CVE-2008-4216)" );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3298" );
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Nov/msg00001.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/15730" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 3.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 200, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/14");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/07");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/Safari/FileVersion");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 3 ||
  (
    iver[0] == 3 &&
    (
      iver[1] < 525 ||
      (
        iver[1] == 525 && 
        (
          iver[2] < 26 ||
          (iver[2] == 26 && iver[3] < 13)
        )
      )
    )
  )
)
{
  if (report_verbosity)
  {
    prod_ver = get_kb_item("SMB/Safari/ProductVersion");
    if (!isnull(prod_ver)) ver = prod_ver;

    report = string(
      "\n",
      "Safari version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
