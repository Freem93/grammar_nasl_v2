#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58801);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2012-2110");
  script_bugtraq_id(53158);
  script_osvdb_id(81223);
  script_xref(name:"EDB-ID", value:"18756");

  script_name(english:"OpenSSL 1.0.1 < 1.0.1a ASN.1 asn1_d2i_read_bio Memory Corruption");
  script_summary(english:"Does a banner check.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be affected by a memory corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL 1.0.1 earlier than 1.0.1a.  As such, the OpenSSL library
itself is reportedly affected by a memory corruption vulnerability via
an integer truncation error in the function 'asn1_d2i_read_bio' when
reading ASN.1 DER format data. 

Applications using the 'BIO' or 'FILE' based functions (i.e.,
'd2i_*_bio' or 'd2i_*_fp' functions) are affected by this issue.  Also
affected are 'S/MIME' or 'CMS' applications using 'SMIME_read_PKCS7'
or 'SMIME_read_CMS' parsers.  The OpenSSL command line utility is
affected if used to handle untrusted DER formatted data. 

Note that the SSL/TLS code of OpenSSL is not affected.  Also not
affected are applications using memory-based ASN.1 functions (e.g.,
'd2i_X509', 'd2i_PKCS12', etc.) nor are applications using only PEM
functions."
  );
  script_set_attribute(attribute:"see_also", value:"http://openssl.org/news/secadv_20120419.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/changelog.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Apr/210");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.1a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.1a', min:"1.0.1", severity:SECURITY_HOLE);
