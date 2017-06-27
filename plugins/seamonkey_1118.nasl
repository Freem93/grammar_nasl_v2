#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40874);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408");
  script_bugtraq_id(35888, 35891);
  script_osvdb_id(56723, 56724, 64070);
  script_xref(name:"Secunia", value:"36125");

  script_name(english:"SeaMonkey < 1.1.18 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute( attribute:"synopsis", value:
"A web browser on the remote host is affected by multiple
vulnerabilities."  );
  script_set_attribute( attribute:"description", value:
"The installed version of SeaMonkey is earlier than 1.1.18.  Such
versions are potentially affected by the following security issues :

  - The browser can be fooled into trusting a malicious SSL
    server certificate with a null character in the host name.
    (MFSA 2009-42)

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
    value:"Upgrade to SeaMonkey 1.1.18 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 310);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/07/30"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/04"
  );
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

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.1.18', severity:SECURITY_HOLE);