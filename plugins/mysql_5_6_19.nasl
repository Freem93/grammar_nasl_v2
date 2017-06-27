#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76530);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/10/17 17:39:52 $");

  script_cve_id(
    "CVE-2014-2484",
    "CVE-2014-4214",
    "CVE-2014-4233",
    "CVE-2014-4238",
    "CVE-2014-4240",
    "CVE-2014-4258",
    "CVE-2014-4260"
  );
  script_bugtraq_id(68560, 68564, 68573, 68587, 68598, 68602, 68607);

  script_name(english:"MySQL 5.6.x < 5.6.19 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.6.x installed on the remote host is prior to
5.6.19.  It is, therefore, affected by vulnerabilities in the following
components :

  - SRCHAR
  - SRFTS
  - SRINFOSC
  - SROPTZR
  - SRREP
  - SRREP
  - SRSP");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-19.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 5.6.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.6.19', min:'5.6', severity:SECURITY_WARNING);
