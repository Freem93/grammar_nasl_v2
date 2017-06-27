#TRUSTED 0dcd65e7b8f54245f6c513a1daa542767a485f740be71bc43a7733d84e3e3d247c146f46f3101ed3263f504dfd063a9716dbb2848871bd303cc7b416355755f15e3484eb2bca17d899016b8b3019899e168d5306565b4e8fef456d228257d257abe1ff0910204fe88dd3d50c7ea90a8c21809a6f1de7eb318d9884e54a2b59bf6bd26361a5b50aa02e95ea5c3a829ffd5abfb3736e557ee02c2868060af8c45a5278501b3e051ff7a803afc618641f10a7d399bf0a4d23a4ce2e77fe2a18667e2a83cadbfd8634a92ef5747aa38e6bd8652ad1ad90e4e79e644d2e2ca4bcb5ec754a234ad99fc741284539b3a502c4fdd337f2c038d1bbb79fb220a2aed9779a351bfaa79be96dd0d48e13ed5942f0c3d615849edeed90dfadb2d7e388fa41ab350b8492a644477ee927e55b9905c58363b441a47b93dff4d91a0551bde0a25d48d6f599eb3bf7bcb7308036b654011516879db4a6e07d3c72d10a6687a963dac355abae9a60a486328b4a391ca90efa1b901e3aaaf3360efafcebf4e30f1431b9ffd66c1888b301d3113eff126f37ec652f0bc16329707d30f5a982e3f0ae59a30931bdfa983e7a6dba7ecb87b1067ac482eca9d3fdd3b366623781ee22059e554a88622a34a2fcbd54a020269f88560924fbcaa537cf33670001f68280b93b3ae0739cbe47e35720140f0e2dd3d7a67b189de38ad608f85d6f0e0e8adfaccf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16151);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id("CVE-2005-0043");
 script_bugtraq_id(12238);
 script_osvdb_id(12833);
 script_xref(name:"Secunia", value:"13804");
 script_xref(name:"APPLE-SA", value:"APPLE-SA-2005-01-11");

 script_name(english:"iTunes < 4.7.1");
 script_summary(english:"Check the version of iTunes");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",  value:
"The remote host is running a version of iTunes which is older than
version 4.7.1.  The remote version of this software is vulnerable
to a buffer overflow when it parses a malformed playlist file
(.m3u or .pls files).  A remote attacker could exploit this by
tricking a user into opening a maliciously crafted file, resulting
in arbitrary code execution." );
 # https://lists.apple.com/archives/security-announce/2005/Jan/msg00000.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eba3be11");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/119");
 script_set_attribute(attribute:"solution", value:"Upgrade to iTunes 4.7.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Apple ITunes 4.7 Playlist Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/01/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("ssh_func.inc");
include("macosx_func.inc");

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

cmd = GetBundleVersionCmd(file:"iTunes.app", path:"/Applications");

if ( islocalhost() )
 buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
else
{
 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}

if ( ! buf ) exit(0);
if ( ! ereg(pattern:"^iTunes [0-9.]", string:buf) ) exit(0);
version = ereg_replace(pattern:"^iTunes ([0-9.]+),.*", string:buf, replace:"\1");
set_kb_item(name:"iTunes/Version", value:version);
if ( egrep(pattern:"iTunes 4\.([0-6]\..*|7|7\.0)$", string:buf) ) security_warning(0);
