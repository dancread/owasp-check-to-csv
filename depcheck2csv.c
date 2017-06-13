#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <libxml/xmlreader.h>
//#include <libxml/xmlversion.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

void parseProject(xmlDocPtr, xmlNodePtr);
void parseDependencies(xmlDocPtr, xmlNodePtr);
void parseVulnerabilities(xmlDocPtr, xmlNodePtr);
void parseVulnerability(xmlDocPtr, xmlNodePtr);
void parseSeverityAndName(xmlDocPtr, xmlNodePtr);
void parseFileName(xmlDocPtr, xmlNodePtr);
void SearchRecursively(LPCTSTR lpFolder, LPCTSTR lpFilePattern);
/* CSV entries:
  project name
  report date
  dependency name
  vulnerability
  severity
*/
struct project_entry {
  xmlChar *project_name;
  xmlChar *dependency_name;
  xmlChar *vuln_name;
  xmlChar *report_date;
  xmlChar *severity;
} project_entry;
int main(int argc, char** argv){
  char szCWD[MAX_PATH];
  GetCurrentDirectory(MAX_PATH,szCWD);
  // Find all files with that name
  SearchRecursively(szCWD,"dependency-check-report.xml");
  return 0;
}
void parseProject(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xmlChar *project_name;
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get project name
    while (xml_ptr != NULL) {
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"name"))) {
        project_entry.project_name = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
        //printf("project name: %s\n", project_name);
        //xmlFree(project_name);
      }
      xml_ptr = xml_ptr->next;
    }
}
void parseDependencies(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xml_ptr = xml_ptr->xmlChildrenNode;

    // Get dependencies
    while (xml_ptr != NULL) {
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"dependency"))) {
        parseFileName(xml_doc, xml_ptr);
        parseVulnerabilities(xml_doc, xml_ptr);
      }
      xml_ptr = xml_ptr->next;
    }
}
void parseFileName(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xmlChar *file_name;
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get file name
    while (xml_ptr != NULL) {
      //printf("%s\n", xml_ptr->name);
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"fileName"))) {
        project_entry.dependency_name = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
		    //printf("%s\n", file_name);
		    //xmlFree(file_name);
      }
      xml_ptr = xml_ptr->next;
    }

}
void parseVulnerabilities(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get vulnerabilities
    while (xml_ptr != NULL) {
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"vulnerabilities"))) {
        parseVulnerability(xml_doc, xml_ptr);
      }
      xml_ptr = xml_ptr->next;
    }

}
void parseVulnerability(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get vulnerability
    while (xml_ptr != NULL) {
      //printf("%s\n", xml_ptr->name);
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"vulnerability"))) {
        parseSeverityAndName(xml_doc, xml_ptr);
      }
      xml_ptr = xml_ptr->next;
    }

}
void parseSeverityAndName(xmlDocPtr xml_doc, xmlNodePtr xml_ptr){
    xmlChar *severity;
    xmlChar *name;
    xml_ptr = xml_ptr->xmlChildrenNode;
    // Get severity
    while (xml_ptr != NULL) {
      //printf("%s\n", xml_ptr->name);
	    if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"severity"))) {
        project_entry.severity = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
		    //printf("\t%s", severity);
		    //xmlFree(severity);
      }
      else if ((!xmlStrcmp(xml_ptr->name, (const xmlChar *)"name"))) {
        project_entry.vuln_name = xmlNodeListGetString(xml_doc, xml_ptr->xmlChildrenNode, 1);
		    //printf("\t%s", name);
		    //xmlFree(name);
      }
      xml_ptr = xml_ptr->next;
    }
    printf("%s,%s,%s,%s\n", project_entry.project_name, project_entry.dependency_name, project_entry.vuln_name, project_entry.severity);
    //printf("\n");

}
void SearchRecursively(LPCTSTR lpFolder, LPCTSTR lpFilePattern)
{
    TCHAR szFullPattern[MAX_PATH];
    WIN32_FIND_DATA FindFileData;
    HANDLE hFindFile;
    // first we are going to process any subdirectories
    PathCombine(szFullPattern, lpFolder, "*");
    hFindFile = FindFirstFile(szFullPattern, &FindFileData);
    if(hFindFile != INVALID_HANDLE_VALUE)
    {
        do
        {
          if(strcmp(FindFileData.cFileName,".") && strcmp(FindFileData.cFileName,"..")){
            if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                // found a subdirectory; recurse into it
                //printf("%s\n", FindFileData.cFileName);
                PathCombine(szFullPattern, lpFolder, FindFileData.cFileName);
                SearchRecursively(szFullPattern, lpFilePattern);
            }
          }
        } while(FindNextFile(hFindFile, &FindFileData));
        FindClose(hFindFile);
    }

    // Now we are going to look for the matching files
    PathCombine(szFullPattern, lpFolder, lpFilePattern);
    hFindFile = FindFirstFile(szFullPattern, &FindFileData);
    if(hFindFile != INVALID_HANDLE_VALUE)
    {
        do
        {
            if(!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                // found a file; do something with it
              PathCombine(szFullPattern, lpFolder, FindFileData.cFileName);
              xmlDocPtr    xml_doc = xmlParseFile(szFullPattern);
              xmlNodePtr   xml_cur_node = xmlDocGetRootElement(xml_doc);
              xml_cur_node = xmlDocGetRootElement(xml_doc);
              xml_cur_node = xml_cur_node->xmlChildrenNode;
              while (xml_cur_node != NULL) {
                  // Get project info
                  if ((!xmlStrcmp(xml_cur_node->name, (const xmlChar *)"projectInfo"))){
                    parseProject(xml_doc, xml_cur_node);
                  }
                  // Get dependencies with vulnerabilities
                  if ((!xmlStrcmp(xml_cur_node->name, (const xmlChar *)"dependencies"))){
                    parseDependencies(xml_doc, xml_cur_node);
                  }
                  xml_cur_node = xml_cur_node->next;
              }
              xmlFreeDoc(xml_doc);
            }
        } while(FindNextFile(hFindFile, &FindFileData));
        FindClose(hFindFile);
    }
}
