#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36130);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2009-1169", "CVE-2009-1302", "CVE-2009-1303",
                "CVE-2009-1304", "CVE-2009-1305");
  script_bugtraq_id(34656, 34235);
  script_osvdb_id(
    53079,
    53960,
    53961,
    53962,
    53963,
    53964,
    53965,
    53966,
    53967,
    53969,
    53970,
    53971,
    53972
  );

  script_name(english:"SeaMonkey < 1.1.16 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute( attribute:"synopsis", value:
"A web browser on the remote host is affected by multiple
vulnerabilities."  );
  script_set_attribute( attribute:"description",  value:
"The installed version of SeaMonkey is earlier than 1.1.16.  Such
versions are potentially affected by the following security issues :

  - An XSL transformation vulnerability can be leveraged 
    with a specially crafted stylesheet to crash the browser
    or to execute arbitrary code. (MFSA 2009-12)

  - Multiple remote memory corruption vulnerabilities exist
    which can be exploited to execute arbitrary code in the
    context of the user running the affected application.
    (MFSA 2009-14)"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-12.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-14.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to SeaMonkey 1.1.16 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/10");
 script_cvs_date("$Date: 2016/12/14 20:22:12 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.1.16', severity:SECURITY_HOLE);