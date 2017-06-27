#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56162);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/29 13:57:36 $");

  script_cve_id("CVE-2011-1945", "CVE-2011-3207", "CVE-2011-3210");
  script_bugtraq_id(47888, 49469, 49471);
  script_osvdb_id(74632, 75229, 75230);
  script_xref(name:"CERT", value:"536044");

  script_name(english:"OpenSSL 1.x < 1.0.0e Multiple Vulnerabilities");
  script_summary(english:"Does a banner check.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by multiple SSL-related
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL 1.x prior to 1.0.0e. It is, therefore, affected by the
following vulnerabilities :

  - An error exists related to ECDSA signatures and binary
    curves. The implementation of curves over binary fields
    could allow a remote, unauthenticated attacker to
    determine private key material via timing attacks.
    (CVE-2011-1945)

  - An error exists in the internal certificate verification
    process that can allow improper acceptance of a 
    certificate revocation list (CRL) if the list's 
    'nextUpdate' field contains a date in the past. Note
    that this internal CRL checking is not enabled by
    default. (CVE-2011-3207)

  - An error exists in the code for the ephemeral
    (EC)DH cipher suites that can allow a remote attacker to
    crash the process. (CVE-2011-3210)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openssl.org/news/secadv_20110906.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/changelog.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=736079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=736087"
  );
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2011/232.pdf");
  # CHANGES file in 1.0.0e noting the fix
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ffc1948");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSL 1.0.0e or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2011/05/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.0e', min:'1.0.0', severity:SECURITY_WARNING);
