#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17837);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2008-7247");
  script_bugtraq_id(38043);
  script_osvdb_id(60664);

  script_name(english:"MySQL < 6.0.9-alpha / 5.5.3 Access Control Weakness");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"Access restrictions can be bypassed on the remote database server.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
6.0.9-alpha / 5.5.3.  As such, it reportedly allows
a remote attacker to bypass access restrictions when the data
directory contains a symbolic link to a different file system.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=oss-security&m=125908040022018&w");
  script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/commits/59711");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=39277");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 6.0.9-alpha / 5.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("mysql_version.inc");
mysql_check_version(fixed:make_list('5.5.3', '6.0.9'), severity:SECURITY_HOLE);
