# @DEPRECATED@
#
# Disabled on 2009/06/19. Deprecated by torture_cgi*
exit(0);

#
# (C) Tenable Network Security, Inc.
#




if(description)
{
 script_id(10672);
 script_version ("$Revision: 1.56 $");
 script_xref(name: "OWASP", value: "OWASP-AC-001");
 
 script_name(english:"Unknown CGI Argument Input Validation Tests (torturecgis)");
 
 desc["english"] = "Synopsis : 

A CGI script may be affected by an input validation vulnerability. 

Description :

This script 'tortures' the arguments of the remote CGIs by attempting
to pass common CGI abuse strings as arguments.  The following general
classes of vulnerabilities are tested to some degree:

   - SQL injection
   - Cross-site Scripting 
   - Remote File Inclusion
   - Directory Traversal sequences (e.g., ../../etc/passwd)
   - Encoded Directory Traversal sequences (e.g., ..%2F..%2Fetc)
   - Command injection (e.g., |/bin/id)

Depending on the input validation test and response from the CGI,
there may be indication of a vulnerability. Please note that
this script is likely to generate false positives. It is strongly
encouraged that each result be verified manually.

*** NOTE: THIS SCRIPT IS NOT MEANT TO REPLACE HUMAN EXAMINATION OR
*** A PROPER APPLICATION AUDIT. THIS SCRIPT IS DESIGNED TO DO 
*** RUDIMENTARY TESTING ONLY

Solution : 

Developers and programmers should use both source code auditing 
tools as well as additional application testing software to 
test for common classes of vulnerabilities. If discovered, they
should be remediated and the fixes integrated into the software
development cycle.

Risk factor : None to High";

 script_description(english:desc["english"]);
 
 script_summary(english:"Tortures the arguments of the remote CGIs");
 
 script_category(ACT_DESTRUCTIVE_ATTACK); # Will mess the remote server
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "httpver.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(0); 
 
 script_add_preference(name:"Send POST requests",
                       type:"checkbox", value:"no");

 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

