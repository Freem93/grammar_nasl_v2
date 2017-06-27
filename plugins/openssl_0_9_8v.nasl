#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58799);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2012-2110", "CVE-2012-2131");
  script_bugtraq_id(53158, 53212);
  script_osvdb_id(81223, 82110);
  script_xref(name:"EDB-ID", value:"18756");

  script_name(english:"OpenSSL < 0.9.8w ASN.1 asn1_d2i_read_bio Memory Corruption");
  script_summary(english:"Does a banner check.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be affected by a memory corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL earlier than 0.9.8w.  As such, the OpenSSL library itself
is reportedly affected by a memory corruption vulnerability via an
integer truncation error in the function 'asn1_d2i_read_bio' when
reading ASN.1 DER format data. 

Applications using the 'BIO' or 'FILE' based functions (i.e., 
'd2i_*_bio' or 'd2i_*_fp' functions) are affected by this issue.
Also affected are 'S/MIME' or 'CMS' applications using
'SMIME_read_PKCS7' or 'SMIME_read_CMS' parsers. The OpenSSL command
line utility is affected if used to handle untrusted DER formatted
data.

Note that the SSL/TLS code of OpenSSL is not affected.  Also not
affected are applications using memory-based ASN.1 functions (e.g.,
'd2i_X509', 'd2i_PKCS12', etc.) nor are applications using only PEM
functions.

Note also that the original fix for CVE-2012-2110 in 0.9.8v was
incomplete because the functions 'BUF_MEM_grow' and
'BUF_MEM_grow_clean', in file 'openssl/crypto/buffer/buffer.c', did
not properly account for negative values of the argument 'len'."
  );
  script_set_attribute(attribute:"see_also", value:"http://openssl.org/news/secadv_20120419.txt");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Apr/210");
  script_set_attribute(attribute:"see_also", value:"http://openssl.org/news/secadv_20120424.txt");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/chngview?cn=22479");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/changelog.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8w or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/24");

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

openssl_check_version(fixed:'0.9.8w', severity:SECURITY_HOLE);
