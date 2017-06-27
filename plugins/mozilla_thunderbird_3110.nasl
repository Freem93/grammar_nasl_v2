#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53596);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/09/18 10:39:01 $");

  script_cve_id(
    "CVE-2011-0069",
    "CVE-2011-0070",
    "CVE-2011-0071",
    "CVE-2011-0072",
    "CVE-2011-0074",
    "CVE-2011-0075",
    "CVE-2011-0077",
    "CVE-2011-0078",
    "CVE-2011-0080",
    "CVE-2011-0081"
  );
  script_bugtraq_id(
    47641,
    47646,
    47647,
    47648,
    47651,
    47653,
    47654,
    47655,
    47656,
    47657,
    47666
  );
  script_osvdb_id(
    72075,
    72076,
    72077,
    72078,
    72080,
    72081,
    72082,
    72083,
    72084,
    72090
  );
  script_xref(name:"Secunia", value:"44407");

  script_name(english:"Mozilla Thunderbird 3.1 < 3.1.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.10. 
Such versions are potentially affected by the following security
issues :

  - An error in the resource protocol can allow directory
    traversal. (CVE-2011-0071)

  - Multiple memory safety issues can lead to application 
    crashes and possibly remote code execution.
    (CVE-2011-0069, CVE-2011-0070, CVE-2011-0072, 
    CVE-2011-0074, CVE-2011-0075, CVE-2011-0077, 
    CVE-2011-0078, CVE-2011-0080, CVE-2011-0081)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-12.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?353363cb");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.10', min:'3.1.0', severity:SECURITY_HOLE);