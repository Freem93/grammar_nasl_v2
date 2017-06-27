#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88698);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195");
  script_bugtraq_id(78623, 78626);
  script_osvdb_id(131038, 131039);

  script_name(english:"MySQL Enterprise Server 5.6.x < 5.6.29 / 5.7.x < 5.7.11 OpenSSL Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL Enterprise Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server uses a version of OpenSSL known to be
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Enterprise Server 5.6 installed on the remote
host is 5.6.x prior to 5.6.29 or 5.7.x prior to 5.7.11. It is,
therefore, affected by multiple vulnerabilities in the included
OpenSSL library :

  - A NULL pointer dereference flaw exists in file
    rsa_ameth.c due to improper handling of ASN.1 signatures
    that are missing the PSS parameter. A remote attacker
    can exploit this to cause the signature verification
    routine to crash, resulting in a denial of service
    condition. (CVE-2015-3194)

  - A flaw exists in the ASN1_TFLG_COMBINE implementation in
    file tasn_dec.c related to handling malformed
    X509_ATTRIBUTE structures. A remote attacker can exploit
    this to cause a memory leak by triggering a decoding
    failure in a PKCS#7 or CMS application, resulting in a
    denial of service. (CVE-2015-3195)");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-29.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-11.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Server version 5.6.29 / 5.7.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");

mysql_check_version(fixed:make_list('5.6.29', '5.7.11'), severity:SECURITY_WARNING, variant:"Enterprise", sslvuln:TRUE);
