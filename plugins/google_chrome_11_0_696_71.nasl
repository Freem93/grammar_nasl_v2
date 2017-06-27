#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54647);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-1801",
    "CVE-2011-1804",
    "CVE-2011-1806",
    "CVE-2011-1807"
  );
  script_bugtraq_id(47963, 47964, 47965, 47966);
  script_osvdb_id(72503, 72504, 72505, 72506);
  script_xref(name:"Secunia", value:"44678");

  script_name(english:"Google Chrome < 11.0.696.71 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 11.0.696.71.  Such versions of Chrome are affected by multiple
vulnerabilities:

  - An unspecified error allows the pop-up blocker to be
    bypassed. (Issue #72189)

  - A stale pointer can be left behind when floating point
    numbers are rendered. (Issue #82546)

  - An unspecified error in the GPU command buffer can lead
    to memory corruption. (Issue #82873)

  - An unspecified error in the handling of blobs can lead
    to out-of-bounds writes. (Issue #82903)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff69daca");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 11.0.696.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'11.0.696.71', severity:SECURITY_HOLE);
