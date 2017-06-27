#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99516);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id(
    "CVE-2016-7055",
    "CVE-2017-3308",
    "CVE-2017-3309",
    "CVE-2017-3329",
    "CVE-2017-3331",
    "CVE-2017-3450",
    "CVE-2017-3453",
    "CVE-2017-3454",
    "CVE-2017-3455",
    "CVE-2017-3456",
    "CVE-2017-3457",
    "CVE-2017-3458",
    "CVE-2017-3459",
    "CVE-2017-3460",
    "CVE-2017-3461",
    "CVE-2017-3462",
    "CVE-2017-3463",
    "CVE-2017-3464",
    "CVE-2017-3465",
    "CVE-2017-3467",
    "CVE-2017-3468",
    "CVE-2017-3599",
    "CVE-2017-3600",
    "CVE-2017-3731",
    "CVE-2017-3732"
  );
  script_bugtraq_id(
    94242,
    95813,
    95814,
    97725,
    97742,
    97747,
    97754,
    97763,
    97765,
    97772,
    97776,
    97791,
    97812,
    97818,
    97820,
    97822,
    97825,
    97826,
    97831,
    97837,
    97845,
    97847,
    97848,
    97849,
    97851
  );
  script_osvdb_id(
    147021,
    151018,
    151020,
    155874,
    155875,
    155876,
    155877,
    155878,
    155879,
    155880,
    155881,
    155884,
    155886,
    155887,
    155888,
    155889,
    155890,
    155891,
    155892,
    155893,
    155894,
    155895,
    155896,
    155897,
    155902
  );
  script_xref(name:"IAVA", value:"2017-A-0118");

  script_name(english:"MySQL 5.7.x < 5.7.18 Multiple Vulnerabilities (April 2017 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.18. It is, therefore, affected by multiple vulnerabilities :

  - A carry propagation error exists in the OpenSSL
    component in the Broadwell-specific Montgomery
    multiplication procedure when handling input lengths
    divisible by but longer than 256 bits. This can result
    in transient authentication and key negotiation failures
    or reproducible erroneous outcomes of public-key
    operations with specially crafted input. A
    man-in-the-middle attacker can possibly exploit this
    issue to compromise ECDH key negotiations that utilize
    Brainpool P-512 curves. (CVE-2016-7055)

  - Multiple unspecified flaws exist in the DML subcomponent
    that allow an authenticated, remote attacker to cause a
    denial of service condition. Note that CVE-2017-3331
    only affects versions 5.7.11 to 5.7.17. (CVE-2017-3308,
    CVE-2017-3331, CVE-2017-3456, CVE-2017-3457,
    CVE-2017-3458)

  - Multiple unspecified flaws exist in the Optimizer
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2017-3309, CVE-2017-3453, CVE-2017-3459)

  - An unspecified flaw exists in the Thread Pooling
    subcomponent that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2017-3329)

  - An unspecified flaw exists in the Memcached subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2017-3450)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to insert
    and delete data contained in the database or cause a
    denial of service condition. (CVE-2017-3454)

  - An unspecified flaw exists in the 'Security: Privileges'
    subcomponent that allows an authenticated, remote
    attacker to insert or delete data contained in the
    database or disclose sensitive information.
    (CVE-2017-3455)

  - An unspecified flaw exists in the Audit Plug-in
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2017-3460)

  - Multiple unspecified flaws exist in the
    'Security: Privileges' subcomponent that allow an
    authenticated, remote attacker to cause a denial of
    service condition. (CVE-2017-3461, CVE-2017-3462,
    CVE-2017-3463)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to update,
    insert, or delete data contained in the database.
    (CVE-2017-3464)

  - An unspecified flaw exists in the 'Security: Privileges'
    subcomponent that allows an authenticated, remote
    attacker to update, insert, or delete data contained in
    the database. (CVE-2017-3465)

  - An unspecified flaw exists in the C API subcomponent
    that allows an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2017-3467)

  - An unspecified flaw exists in the 'Security: Encryption'
    subcomponent that allows an authenticated, remote
    attacker to update, insert, or delete data contained in
    the database. (CVE-2017-3468)

  - An unspecified flaw exists in the Pluggable Auth
    subcomponent that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2017-3599)

  - An unspecified flaw exists in the 'Client mysqldump'
    subcomponent that allows an authenticated, remote
    attacker to execute arbitrary code. (CVE-2017-3600)

  - An out-of-bounds read error exists in the OpenSSL
    component when handling packets using the
    CHACHA20/POLY1305 or RC4-MD5 ciphers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted truncated packets, to cause a denial
    of service condition. (CVE-2017-3731)

  - A carry propagating error exists in the OpenSSL
    component in the x86_64 Montgomery squaring
    implementation that may cause the BN_mod_exp() function
    to produce incorrect results. An unauthenticated, remote
    attacker with sufficient resources can exploit this to
    obtain sensitive information regarding private keys.
    (CVE-2017-3732)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-18.html");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54d9438d");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e1362c");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2244179.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.7.18', min:'5.7', severity:SECURITY_HOLE);
