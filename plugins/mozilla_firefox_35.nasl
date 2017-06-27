#
# (C) Tenable Network Security, Inc.
#

# @DEPRECATED@
#
# these two bugs (MFSA 2009-42 and MFSA 2009-43) are already covered by
# mozilla_firefox_3013.nasl
exit(0);

include("compat.inc");


if (description)
{
  script_id(40471);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2012/10/01 15:29:28 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408");
  script_bugtraq_id(35888, 35891);
  script_osvdb_id(56724);
  script_xref(name:"Secunia", value:"36088");

  script_name(english:"Firefox < 3.5 Multiple Flaws");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute( attribute:"synopsis",  value:
"The remote Windows host contains a web browser that is
affected by multiple flaws."  );
  script_set_attribute( attribute:"description",  value:
"The installed version of Firefox is earlier than 3.5.  Such
versions are potentially affected by the following security issues :

  - The browser can be fooled into trusting a malicious
    SSL server certificate with a null character in the host
    name. (MFSA 2009-42)

  - A heap overflow in the code that handles regular
    expressions in certificate names can lead to
    arbitrary code execution. (MFSA 2009-43)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-43.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/03");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0, "No Firefox installations were detected.");

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] < 5)
) security_hole(get_kb_item("SMB/transport"));
