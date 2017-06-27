#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94164);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/23 17:47:51 $");

  script_cve_id(
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2107",
    "CVE-2016-2109",
    "CVE-2016-2176",
    "CVE-2016-5489",
    "CVE-2016-5517",
    "CVE-2016-5532",
    "CVE-2016-5557",
    "CVE-2016-5562",
    "CVE-2016-5567",
    "CVE-2016-5570",
    "CVE-2016-5571",
    "CVE-2016-5575",
    "CVE-2016-5581",
    "CVE-2016-5583",
    "CVE-2016-5585",
    "CVE-2016-5586",
    "CVE-2016-5587",
    "CVE-2016-5589",
    "CVE-2016-5591",
    "CVE-2016-5592",
    "CVE-2016-5593",
    "CVE-2016-5595",
    "CVE-2016-5596"
  );
  script_bugtraq_id(
    87940,
    89744,
    89746,
    89757,
    89760,
    93690,
    93694,
    93699,
    93703,
    93707,
    93721,
    93724,
    93729,
    93738,
    93739,
    93743,
    93747,
    93750,
    93756,
    93758,
    93761,
    93762,
    93764,
    93769,
    93770
  );
  script_osvdb_id(
    137577,
    137896,
    137897,
    137898,
    137899,
    145877,
    145878,
    145879,
    145880,
    145881,
    145882,
    145883,
    145884,
    145885,
    145886,
    145887,
    145888,
    145889,
    145890,
    145891,
    145892,
    145893,
    145894,
    145895,
    145896
  );
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (October 2016 CPU)");
  script_summary(english:"Checks for the October 2016 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the October 2016 Oracle Critical Patch Update (CPU). It is,
therefore, affected by multiple vulnerabilities :

  - A heap buffer overflow condition exists in the OpenSSL
    subcomponent in the EVP_EncodeUpdate() function within
    file crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - A heap buffer overflow condition exists in the OpenSSL
    subcomponent in the EVP_EncryptUpdate() function within
    file crypto/evp/evp_enc.c that is triggered when
    handling a large amount of input data after a previous
    call occurs to the same function with a partial block.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-2106)

  - Multiple flaws exist in the OpenSSL subcomponent in the
    aesni_cbc_hmac_sha1_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha1.c and the
    aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    (CVE-2016-2107)

  - Multiple unspecified flaws exist in the OpenSSL
    subcomponent in the d2i BIO functions when reading ASN.1
    data from a BIO due to invalid encoding causing a large
    allocation of memory. An unauthenticated, remote
    attacker can exploit these to cause a denial of service
    condition through resource exhaustion. (CVE-2016-2109)

  - An out-of-bounds read error exists in the OpenSSL
    subcomponent in the X509_NAME_oneline() function within
    file crypto/x509/x509_obj.c when handling very long ASN1
    strings. An unauthenticated, remote attacker can exploit
    this to disclose the contents of stack memory.
    (CVE-2016-2176)

  - An unspecified flaw exists in the Runtime Catalog
    subcomponent in the iStore component that allows an
    unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2016-5489)

  - An unspecified flaw exists in the AD Utilities
    subcomponent in the Applications DBA component that
    allows a local attacker to disclose sensitive
    information. (CVE-2016-5517)
 
  - An unspecified flaw exists in the Workflow Events
    subcomponent in the Shipping Execution component that
    allows an unauthenticated, remote attacker to disclose
    sensitive information. (CVE-2016-5532)

  - An unspecified flaw exists in the Price Book
    subcomponent in the Advanced Pricing component that
    allows an unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2016-5557)

  - An unspecified flaw exists in the Requisition Management
    subcomponent in the iProcurement component that allows
    an unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2016-5562)

  - Multiple unspecified flaws exist in the AD Utilities
    subcomponent in the DBA component that allow an
    authenticated, remote attacker to impact confidentiality
    and integrity. (CVE- 2016-5567, CVE-2016-5570,
    CVE-2016-5571)

  - An unspecified flaw exists in the Resources Module
    subcomponent in the Common Applications Calendar
    component that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5575)

  - An unspecified flaw exists in the Candidate Self Service
    subcomponent in the iRecruitment component that allows a
    local attacker to gain elevated privileges.
    (CVE-2016-5581)

  - An unspecified flaw exists in the File Upload
    subcomponent in the One-to-One Fulfillment component
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2016-5583)

  - An unspecified flaw exists in the Select Application
    Dependencies subcomponent in the Interaction Center
    Intelligence component that allow an unauthenticated,
    remote attacker to impact confidentiality and integrity.
    (CVE-2016-5585)

  - An unspecified flaw exists in the Dispatch/Service Call
    Requests subcomponent in the Email Center component that
    allow an unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2016-5586)

  - Multiple unspecified flaws exist in the Outcome-Result
    subcomponent in the Customer Interaction History
    component that allow an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2016-5587, CVE-2016-5591, CVE-2016-5593)

  - An unspecified flaw exists in the Responsibility
    Management subcomponent in the CRM Technical Foundation
    component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2016-5589)

  - Multiple unspecified flaws exist in the Result-Reason
    subcomponent in the Customer Interaction History
    component that allow an unauthenticated, remote attacker
    to impact confidentiality and integrity. (CVE-2016-5592,
    CVE-2016-5595)

  - An unspecified flaw exists in the Default Responsibility
    subcomponent in the CRM Technical Foundation component
    that allows an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2016-5596)");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/04/22");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/20");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:e-business_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Oracle/E-Business/Version");
patches = get_kb_item_or_exit("Oracle/E-Business/patches/installed");

# Batch checks
if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

p12_1 = '24390793';
p12_2 = '24390794';

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.1', make_list(p12_1),
  '12.1.2', make_list(p12_1),
  '12.1.3', make_list(p12_1),

  '12.2.3', make_list(p12_2),
  '12.2.4', make_list(p12_2),
  '12.2.5', make_list(p12_2),
  '12.2.6', make_list(p12_2)
);

patched = FALSE;
affectedver = FALSE;

if (affected_versions[version])
{
  affectedver = TRUE;
  patchids = affected_versions[version];
  foreach required_patch (patchids)
  {
    foreach applied_patch (patches)
    {
      if(required_patch == applied_patch)
      {
        patched = applied_patch;
        break;
      }
    }
    if(patched) break;
  }
  if(!patched) patchreport = join(patchids,sep:" or ");
}

if (!patched && affectedver)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+version+' Patch '+patchreport+
      '\n';
    security_hole(port:0,extra:report);
  }
  else security_hole(0);
  exit(0);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
