#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50476);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id(
    "CVE-2010-4008",
    "CVE-2010-4197",
    "CVE-2010-4198",
    "CVE-2010-4203",
    "CVE-2010-4204",
    "CVE-2010-4206"
  );
  script_bugtraq_id(44646, 44771, 44779, 45718, 45719, 45720, 45721);
  script_osvdb_id(69163, 69164, 69169, 69170, 69172, 69205);
  script_xref(name:"Secunia", value:"42109");

  script_name(english:"Google Chrome < 7.0.517.44 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 7.0.517.44.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A use-after-free error exists in text editing.
    (Issue #51602)

  - A memory corruption error exists relating to enormous
    text area. (Issue #55257)

  - A bad cast exists with the SVG use element.
    (Issue #58657)

  - An invalid memory read exists in XPath handling.
    (Issue #58731)

  - A use-after-free error exists in text control
    selections. (Issue #58741)

  - A memory corruption issue exists in libvpx.
    (Issue #60055)

  - A bad use of a destroyed frame object exists.
    (Issue #60238)

  - Multiple type confusions exists with event objects.
    (Issue #60327, #60769, #61255)

  - An out-of-bounds array access exists in SVG handling.
    (Issue #60688)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc6b8a66");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 7.0.517.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'7.0.517.44', severity:SECURITY_HOLE);
