#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59077);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/15 21:16:06 $");

  script_cve_id("CVE-2012-2333");
  script_bugtraq_id(53476);
  script_osvdb_id(81810);

  script_name(english:"OpenSSL 1.0.0 < 1.0.0j DTLS CBC Denial of Service");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be affected by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL 1.0.0 earlier than 1.0.0j. As such, the OpenSSL library
itself is reportedly affected by a denial of service vulnerability.

An integer underflow error exists in the file 'ssl/d1_enc.c' in the
function 'dtls1_enc'. When in CBC mode, DTLS record length values and
explicit initialization vector length values related to DTLS packets
are not handled properly, which can lead to memory corruption and
application crashes."
  );
  script_set_attribute(attribute:"see_also", value:"http://openssl.org/news/secadv_20120510.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/changelog.html");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/chngview?cn=22538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=820686");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.0j or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");


openssl_check_version(fixed:'1.0.0j', min:"1.0.0", severity:SECURITY_WARNING);
