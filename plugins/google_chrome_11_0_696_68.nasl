#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53879);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2011-1799", "CVE-2011-1800");
  script_bugtraq_id(47828, 47830);
  script_osvdb_id(72369, 72370);
  script_xref(name:"Secunia", value:"44591");

  script_name(english:"Google Chrome < 11.0.696.68 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 11.0.696.68.  Such versions of Chrome are affected by multiple
vulnerabilities:

  - Multiple variable cast errors exist in the WebKit glue
    code. These errors can be exploited and allow an
    attacker to execute arbitrary code or crash the
    the application. (Issue #64046)

  - Multiple integer overflows exist in the SVG filters.
    These errors can be exploited and allow an attacker to
    execute arbitrary code or crash the application.
    (Issue #80608)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b79e4c8b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 11.0.696.68 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/12");

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
google_chrome_check_version(installs:installs, fix:'11.0.696.68', severity:SECURITY_HOLE);
