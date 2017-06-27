#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40554);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-2188", "CVE-2009-2195", "CVE-2009-2196",
                "CVE-2009-2199", "CVE-2009-2200", "CVE-2009-2468");
  script_bugtraq_id(36022, 36023, 36024, 36025, 36026);
  script_osvdb_id(56385, 56842, 56986, 56987, 56988, 56989);

  script_name(english:"Safari < 4.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute( attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
vulnerabilities."  );
  script_set_attribute( attribute:"description",  value:
"The version of Safari installed on the remote Windows host is earlier
than 4.0.3.  Such versions are potentially affected by several
issues :

  - A buffer overflow exists in the handling of EXIF
    metadata that ccould lead to a crash or arbitrary code
    execution. (CVE-2009-2188)

  - A vulnerability in WebKit's parsing of floating point
    numbers may allow for remote code execution.
    (CVE-2009-2195)

  - A vulnerability in Safari may allow a malicious website
    to be promoted in Safari's Top Sites. (CVE-2009-2196)

  - A vulnerability in how WebKit renders an URL with look-
    alike characters could be used to masquerade a website.
    (CVE-2009-2199)

  - A vulnerability in WebKit may lead to the disclosure of
    sensitive information. (CVE-2009-2200)

  - A heap-based buffer overflow in CoreGraphics involving
    the drawing of long text strings could lead to a crash
    or arbitrary code execution. (CVE-2009-2468)");
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Aug/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/17616"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Safari 4.0.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 200);
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/11"
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
  ver[0] < 4 ||
  (
    ver[0] == 4 &&
    (
      ver[1] < 531 ||
      (
        ver[1] == 531 && 
        (
          ver[2] < 9 ||
          (ver[2] == 9 && ver[3] < 1)
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
