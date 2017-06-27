#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57605);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0490", "CVE-2012-0492", "CVE-2012-0583");
  script_bugtraq_id(51488, 51493, 51502, 51504, 51505, 51508, 51509, 51511, 51512, 51513, 51515, 51516, 51517, 51519, 51520, 51524, 51526, 53061);
  script_osvdb_id(
    78368,
    78369,
    78370,
    78372,
    78373,
    78374,
    78376,
    78377,
    78378,
    78379,
    78380,
    78381,
    78382,
    78383,
    78388,
    78391,
    78393,
    81374
  );

  script_name(english:"MySQL 5.1 < 5.1.61 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.61.  Such versions are affected by multiple, as yet unspecified
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ebfd596");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abcc17ed");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.1.61 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.1.61', min:'5.1', severity:SECURITY_WARNING);
