#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42413);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/11/13 21:35:39 $");

  script_cve_id("CVE-2009-3931", "CVE-2009-3932");
  script_bugtraq_id(36947);
  script_osvdb_id(59742, 59743, 59744, 59745);
  script_xref(name:"Secunia", value:"37273");

  script_name(english:"Google Chrome < 3.0.195.32 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 3.0.195.32.  Such versions are reportedly affected by multiple
issues :

  - The user is not warned about certain dangerous file
    types such as 'SVG', 'MHT', and 'XML'. In some browsers,
    JavaScript can execute within these types of files.
    (Issue #23979)

  - A malicious site could use the Gears SQL API to put SQL
    metadata into a bad state, which could cause a
    subsequent memory corruption which could lead the Gears
    plugin to crash, or possibly allow arbitrary code
    execution. (Issue #26179)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1adc32dc");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5c8ae4f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 3.0.195.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'3.0.195.32', severity:SECURITY_HOLE);
