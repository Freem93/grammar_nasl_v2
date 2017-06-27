#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40664);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2009-2408");
  script_bugtraq_id(35888);
  script_osvdb_id(56723);
  script_xref(name:"Secunia", value:"36088");

  script_name(english:"Mozilla Thunderbird < 2.0.0.23 Certificate Authority (CA) Common Name Null Byte Handling SSL MiTM Weakness");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote Windows host contains a mail client that is affected by a
security bypass vulnerability."  );
  script_set_attribute(  attribute:"description",  value:
"The installed version of Thunderbird is earlier than 2.0.0.23.  Such
versions are potentially affected by the following security issue :

  - The client can be fooled into trusting a malicious SSL
    server certificate with a null character in the host name.
    (MFSA 2009-42)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-42.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Thunderbird 2.0.0.23 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/07/30"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/20"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/21"
  );
 script_cvs_date("$Date: 2016/05/16 14:12:51 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.23', severity:SECURITY_WARNING);