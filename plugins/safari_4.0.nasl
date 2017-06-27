#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39339);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id("CVE-2006-2783", "CVE-2008-1588", "CVE-2008-2320", "CVE-2008-2321",
                "CVE-2008-3281", "CVE-2008-3529", "CVE-2008-3632", "CVE-2008-4225",
                "CVE-2008-4226", "CVE-2008-4231", "CVE-2008-4409", "CVE-2009-0040",
                "CVE-2009-0145", "CVE-2009-0153", "CVE-2009-0946", "CVE-2009-1179",
                "CVE-2009-1681", "CVE-2009-1682", "CVE-2009-1684", "CVE-2009-1685",
                "CVE-2009-1686", "CVE-2009-1687", "CVE-2009-1688", "CVE-2009-1689",
                "CVE-2009-1690", "CVE-2009-1691", "CVE-2009-1693", "CVE-2009-1694",
                "CVE-2009-1695", "CVE-2009-1696", "CVE-2009-1697", "CVE-2009-1698",
                "CVE-2009-1699", "CVE-2009-1700", "CVE-2009-1701", "CVE-2009-1702",
                "CVE-2009-1703", "CVE-2009-1704", "CVE-2009-1705", "CVE-2009-1706",
                "CVE-2009-1707", "CVE-2009-1708", "CVE-2009-1709", "CVE-2009-1710",
                "CVE-2009-1711", "CVE-2009-1712", "CVE-2009-1713", "CVE-2009-1714",
                "CVE-2009-1715", "CVE-2009-1716", "CVE-2009-1718", "CVE-2009-2027",
                "CVE-2009-2420", "CVE-2009-2421");
  script_bugtraq_id(30487, 31092, 32326, 33276, 35260, 35270, 35271, 35272, 35283,
                    35284, 35308, 35309, 35310, 35311, 35315, 35317, 35318, 35319,
                    35320, 35321, 35322, 35325, 35327, 35328, 35330, 35331, 35332,
                    35333, 35334, 35339, 35340, 35344, 35346, 35347, 35348, 35349,
                    35350, 35351, 35352, 35353, 35481, 35482);
  script_osvdb_id(
    47286,
    47636,
    48158,
    48472,
    48568,
    48569,
    48754,
    49992,
    49993,
    50028,
    53315,
    53316,
    53317,
    54068,
    54069,
    54070,
    54447,
    54451,
    54476,
    54477,
    54478,
    54972,
    54973,
    54974,
    54975,
    54981,
    54982,
    54983,
    54984,
    54985,
    54986,
    54987,
    54988,
    54989,
    54991,
    54992,
    54993,
    54994,
    54995,
    54996,
    54997,
    55004,
    55005,
    55006,
    55008,
    55009,
    55010,
    55011,
    55012,
    55013,
    55014,
    55015,
    55021,
    55022,
    55023,
    55027,
    55769,
    55783
  );

  script_name(english:"Safari < 4.0 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Safari installed on the remote Windows host is earlier
than 4.0.  It therefore is potentially affected by numerous issues in
the following components :

  - CFNetwork
  - CoreGraphics
  - ImageIO
  - International Components for Unicode
  - libxml
  - Safari
  - Safari Windows Installer
  - WebKit");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3613");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Jun/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/17079");
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 94, 119, 189, 200, 255, 264, 310, 362, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/09");

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
      (ver[1] == 530 && ver[2] < 17)
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
