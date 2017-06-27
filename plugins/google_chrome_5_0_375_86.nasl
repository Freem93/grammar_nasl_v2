#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47139);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_bugtraq_id(41138);
  script_osvdb_id(67263, 67264, 67265, 67266);
  script_xref(name:"Secunia", value:"40351");

  script_name(english:"Google Chrome < 5.0.375.86 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 5.0.375.86.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability. (Issue #38105)

  - Several memory errors exist when handling video.
    (Issue #43322, #45267)

  - An information disclosure vulnerability exists in
    omnibox loading. (Issue #43967)

  - A stale pointer exists in the x509-user-cert response.
    (Issue #46126)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce922261");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 5.0.375.86 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'5.0.375.86', xss:TRUE, severity:SECURITY_HOLE);
