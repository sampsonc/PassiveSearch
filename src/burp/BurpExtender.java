/*
 * The MIT License
 *
 * Copyright 2020 Carl Sampson <chs@chs.us>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package burp;

import search.ScanMatch;
import search.ScanIssue;
import search.SearchTab;
import search.SearchComponent;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.DefaultListModel;

/**
 *
 * @author Carl Sampson <chs@chs.us>
 */
public class BurpExtender implements IBurpExtender, IScannerCheck
{

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    private SearchComponent comp;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        //Get references to callbacks and such
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.output = callbacks.getStdout();
        
        //Set the extention name.  This what is shown under the Extensions tab
        callbacks.setExtensionName("Passive Search");
        
        //Register this extension as a scanner check
        callbacks.registerScannerCheck(this);
        
        //Add UI
        SearchTab tab = new SearchTab("Passive Search", callbacks);
        comp = new SearchComponent(callbacks, this);
        tab.addComponent(comp);  
        
        println("Passive Search Loaded");        
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        //Make sure passive scanning is enabled
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();  //Get the URL  

        //Figure out what the body offset is so we can work with the response
        byte[] response = baseRequestResponse.getResponse();
        int bodyOffset = this.helpers.analyzeResponse(response).getBodyOffset();        
        List<IScanIssue> totalIssues = new ArrayList<>();
        
        //Look for search terms specified in the configuration in headers if enabled
        if (comp.isPassiveHeaderEnabled())
        {
            byte [] headers = Arrays.copyOfRange(response, 0, bodyOffset - 1);
            List<IScanIssue> headerIssues = scanPassive(headers, 0, baseRequestResponse, "Headers");
            totalIssues.addAll(headerIssues);
        }
        
        //Look for search terms specified in the configuration in body if enabled
        if (comp.isPassiveBodyEnabled())            
        {
            byte[] body = Arrays.copyOfRange(response, bodyOffset, response.length);
            List<IScanIssue> bodyIssues = scanPassive(body, bodyOffset, baseRequestResponse, "Body");
            totalIssues.addAll(bodyIssues);
        }
        
        //If there are any matches, then build the issue and return it
        if (totalIssues.size() > 0)
        {
            return totalIssues;
        }
        else 
        {
            return null;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {        
       return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) 
        {
            //println("Consolidating Duplicate Issue.");
            return -1;
        }
        return 0;
    }
    
    public void println(String toPrint)
    {
        try 
        {
            this.output.write("Passive Search Plugin -- ".getBytes());
            this.output.write(toPrint.getBytes());
            this.output.write("\n".getBytes());
            this.output.flush();
        } 
        catch (IOException ioe) 
        {            
        }
    }      
    
    //Passively search for all items in the configuration
    private List<IScanIssue> scanPassive( byte[] text, int offSet, IHttpRequestResponse baseRequestResponse, String location)
    {
        DefaultListModel<String> model = comp.getModel();
        List<IScanIssue> issues = new ArrayList<>();

        if (model != null)
        {
            for (int i = 0; i < model.getSize(); i++)
            {
                String term = model.getElementAt(i);
                Pattern pattern = Pattern.compile(term, Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(new String(text));
                List <ScanMatch>matches = new ArrayList<>(); //Possible places for search results

                while (matcher.find())
                {
                    matches.add(new ScanMatch(matcher.group(), matcher.start() + offSet, matcher.end() + offSet, ""));
                }
                
                if (matches.size() > 0)
                {            
                    ScanMatch [] arrMatches = new ScanMatch[matches.size()];
                    matches.toArray(arrMatches);
                    Arrays.sort(arrMatches);

                    List <int[]> startStop = new ArrayList<>();  //List of start and stop positions for items

                    //Build the issue if there are matches
                    StringBuilder description = new StringBuilder();
                    description.append("One or more of your search terms was found from Scan Items.<br/><br/>");
                    description.append("<b>Parameter details</b><br/><br/>");

                    description.append("The following search terms have been found in the response:<br>");        
                    description.append("<ul>");            
                    for (ScanMatch match: arrMatches)
                    {
                        startStop.add(new int[] { match.getStart(), match.getEnd() });
                        description.append("<li>");
                        description.append(match.getMatch());
                        description.append("</li>");
                    }
                    description.append("</ul>");    

                    //Add the issue
                    issues.add(new ScanIssue(baseRequestResponse.getHttpService(), this.helpers.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[] { this.callbacks.applyMarkers(baseRequestResponse, null, startStop) }, "Search Term \"" + term + "\" found in the " + location, description.toString(), "Information", "Certain"));
                }

            }
        }
        return issues;
    }
}