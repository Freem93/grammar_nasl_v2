#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93383);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id(
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-3195"
  );
  script_bugtraq_id(
    75156,
    75157,
    75161,
    78626
  );
  script_osvdb_id(
    122875,
    123173,
    123174,
    131039
  );
  script_xref(name:"JSA", value:"JSA10733");
  script_xref(name:"IAVA", value:"2016-A-0231");
  script_xref(name:"IAVA", value:"2016-A-0293");

  script_name(english:"Juniper ScreenOS 6.3.x < 6.3.0r22 Multiple Vulnerabilities in OpenSSL (JSA10733)");
  script_summary(english:"Checks the version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Juniper ScreenOS running on the remote host is 6.3.x
prior to 6.3.0r22. It is, therefore, affected by multiple
vulnerabilities in its bundled version of OpenSSL :

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the ASN1_TIME
    string by the X509_cmp_time() function. A remote
    attacker can exploit this, via a malformed certificate
    and CRLs of various sizes, to cause a segmentation
    fault, resulting in a denial of service condition. TLS
    clients that verify CRLs are affected. TLS clients and
    servers with client authentication enabled may be
    affected if they use custom verification callbacks.
    (CVE-2015-1789)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing inner
    'EncryptedContent'. This allows a remote attacker, via
    specially crafted ASN.1-encoded PKCS#7 blobs with
    missing content, to cause a denial of service condition
    or other potential unspecified impacts. (CVE-2015-1790)

  - A double-free error exists due to a race condition that
    occurs when a NewSessionTicket is received by a
    multi-threaded client when attempting to reuse a
    previous ticket. A remote attacker can exploit this to
    cause a denial of service condition or other potential
    unspecified impact. (CVE-2015-1791)

  - A flaw exists in the ASN1_TFLG_COMBINE implementation in
    file tasn_dec.c related to handling malformed
    X509_ATTRIBUTE structures. A remote attacker can exploit
    this to cause a memory leak by triggering a decoding
    failure in a PKCS#7 or CMS application, resulting in a
    denial of service. (CVE-2015-3195)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10733");
  # http://www.juniper.net/techpubs/en_US/screenos6.3.0/information-products/pathway-pages/screenos/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4eb1929");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS version 6.3.0r22 or later. Alternatively,
refer to the vendor advisory for additional workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/06/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:juniper:screenos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
version = get_kb_item_or_exit("Host/Juniper/ScreenOS/version");

# prior to 6.3.0r22 are affected. 6.2 unsupported
# fix is 6.3.0r22 and later
if (version =~ "^6\.3([^0-9]|$)" && ver_compare(ver:version, fix:"6.3.0.22", strict:FALSE) < 0)
{
  display_fix = "6.3.0r22";

  port = 0;
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
