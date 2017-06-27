#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39767);
  script_version("$Revision: 1.11 $");


  script_cve_id("CVE-2009-1724", "CVE-2009-1725");
  script_bugtraq_id(35441, 35607);
  script_osvdb_id(55738, 55739);

  script_name(english:"Safari < 4.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute( attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
vulnerabilities."  );
  script_set_attribute( attribute:"description",   value:
"The version of Safari installed on the remote Windows host is earlier
than 4.0.2.  Such versions are potentially affected by two issues :

  - A vulnerability in WebKit's handling of parent and top
    objects may allow for cross-site scripting attacks.
    (CVE-2009-1724)

  - A memory corruption issue in WebKit's handling of
    numeric character references could lead to a crash or 
    arbitrary code execution. (CVE-2009-1725)"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3666"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Jul/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17297"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 4.0.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 189);
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/08"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/09"
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
      ver[1] < 530 ||
      (
        ver[1] == 530 && 
        (
          ver[2] < 19 ||
          (ver[2] == 19 && ver[3] < 1)
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
