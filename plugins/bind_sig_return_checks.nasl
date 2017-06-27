#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38735);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/05/02 23:36:52 $");

  script_cve_id("CVE-2009-0025");
  script_bugtraq_id(33151);
  script_osvdb_id(51368);
  script_xref(name:"Secunia", value:"33404");

  script_name(english:"ISC BIND 9 EVP_VerifyFinal() / DSA_do_verify() SSL/TLS Signature Validation Weakness");
  script_summary(english:"Checks the version of BIND");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is affected by a signature validation weakness.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote installation of BIND does
not properly check the return value from the OpenSSL library functions
'EVP_VerifyFinal()' and 'DSA_do_verify()'. A remote attacker may be
able to exploit this weakness to spoof answers returned from zones for
signature checks on DSA and ECDSA keys used with SSL / TLS.");
  # https://kb.isc.org/article/AA-00925/0/CVE-2009-0025%3A-EVP_VerifyFinal-and-DSA_do_verify-return-checks.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a61b5626");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND 9.3.6-P1 / 9.4.3-P1 / 9.5.1-P1 / 9.6.0-P1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl", "dnssec_resolver.nasl");
  script_require_keys("bind/version", "DNSSEC/udp/53", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# nb: don't bother if the host doesn't support DNSSEC.
if (isnull(get_kb_item("DNSSEC/udp/53"))) exit(0);


ver = get_kb_item("bind/version");
if (
  ver &&
  ver =~ "^9\.([0-2]\.[0-9\.]+|3\.([0-5]{1}|6$)|4\.([0-2]{1}|3$)|5\.(0{1}|1$)|6\.0$)"
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "BIND ", ver, " appears to be installed on the remote host.\n"
    );
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
}
