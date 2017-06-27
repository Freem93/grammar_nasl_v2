#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52975);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-1291",
    "CVE-2011-1292",
    "CVE-2011-1293",
    "CVE-2011-1294",
    "CVE-2011-1295",
    "CVE-2011-1296"
  );
  script_bugtraq_id(47029);
  script_osvdb_id(72262, 72263, 72264, 72265, 72266, 72267);
  script_xref(name:"Secunia", value:"43859");

  script_name(english:"Google Chrome < 10.0.648.204 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 10.0.648.204.  Such versions of Chrome are affected by multiple
vulnerabilities:

  - A buffer error exists in string handling functions.
    (Issue #72517)

  - A use-after-free error exists in the processes for
    loading frames. (Issue #73216)

  - A use-after-free error exists in the processing of
    HTML Collections. (Issue #73595)

  - An error exists in the processing of CSS which leaves
    stale pointers behind. (Issue #74562)

  - An unspecified error allows DOM tree corruption related
    to broken node-hierarchy. (Issue #74991)

  - An error exists in the processing of SVG text which
    leaves stale pointers behind. (Issue #75170)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f43cc2df");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 10.0.648.204 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/25");

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
google_chrome_check_version(installs:installs, fix:'10.0.648.204', severity:SECURITY_HOLE);
