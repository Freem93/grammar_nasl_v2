#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58074);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2011-3026");
  script_bugtraq_id(52049);
  script_osvdb_id(79294);

  script_name(english:"Firefox < 10.0.2 png_decompress_chunk Integer Overflow (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is potentially
affected by an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 10.0.2 and is,
therefore, potentially affected by an integer overflow vulnerability
in libpng, a library used by this application.  When decompressing
certain PNG image files, this could be exploited to crash the
application or even execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-11/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6846f277");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 10.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'10.0.2', skippat:'3\\.6\\.', severity:SECURITY_HOLE);
