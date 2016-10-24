package burp;

import com.codemagi.burp.BaseExtender;
import com.codemagi.burp.Utils;
import com.codemagi.burp.parser.Cookie;
import com.codemagi.burp.parser.HttpRequest;
import java.awt.BorderLayout;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.JFrame;
import javax.swing.JMenuItem;

/**
 * Burp Extender to discover the session cookies
 *
 * This extension attempts to determine which cookie(s) are tracking session
 * state. It issues the same request multiple times dropping one cookie at a
 * time. It then tests the response for a match string that indicates whether
 * the session is still active.
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class BurpExtender extends BaseExtender implements IBurpExtender, IContextMenuFactory {

    @Override
    protected void initialize() {
        //set the extension Name
        extensionName = "Session Discovery";

        //set the settings namespace (subclasses should override this)
        settingsNamespace = "SD_";

        // register ourselves as a Context Menu Factory
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        //get information from the invocation
        IHttpRequestResponse[] ihrrs = invocation.getSelectedMessages();
        callbacks.printOutput("response: " + Arrays.toString(ihrrs[0].getResponse()));

        int[] offsets = invocation.getSelectionBounds();
        callbacks.printOutput("offsets: " + Arrays.toString(offsets));

        List<JMenuItem> menuItems = new ArrayList<>();

        JMenuItem item = new JMenuItem("Session Discovery");
        item.addActionListener(new MenuItemListener(ihrrs, Utils.getSelection(ihrrs[0].getResponse(), offsets)));
        menuItems.add(item);

        return menuItems;
    }

    class MenuItemListener implements ActionListener {

        private final IHttpRequestResponse[] requestResponse;
        private final String selection;

        public MenuItemListener(IHttpRequestResponse[] ihrrs, String selection) {
            requestResponse = ihrrs;
            this.selection = selection;
        }

        @Override
        public void actionPerformed(ActionEvent ae) {
            //create a Java GUI to get the test parameters (match string, mix/max session length, increment)
            initializeGUI(requestResponse, selection);
        }
    }

    public void launchScan(IHttpRequestResponse[] ihrrs, String timeoutMatchString, SessionDiscoveryPanel panel) throws IOException {
        callbacks.printOutput("launching scan! " + ihrrs.length);

        //this is only intended to work with ONE request
        if (ihrrs.length > 1) {
            callbacks.printOutput("The Session Discovery Extension only works with one request at a time -EXITING");
            return;
        }

        //launch a scanner thread
        TestThread theScan = new TestThread(ihrrs[0], timeoutMatchString, panel);
        theScan.start();
    }

    class TestThread extends Thread {

        IHttpRequestResponse baseRequestResponse;
        String timeoutMatchString;
        SessionDiscoveryPanel panel;

        public TestThread(IHttpRequestResponse baseRequestResponse, String timeoutMatchString, SessionDiscoveryPanel panel) {
            this.baseRequestResponse = baseRequestResponse;
            this.timeoutMatchString = timeoutMatchString;
            this.panel = panel;
        }

        @Override
        public void run() {
            callbacks.printOutput("baseRequestResponse: " + baseRequestResponse);
            IHttpService service = baseRequestResponse.getHttpService();
            callbacks.printOutput("service: " + service);

            //parse the request to get the cookies
            byte[] request = baseRequestResponse.getRequest();
            HttpRequest originalRequest;
            try {
                originalRequest = HttpRequest.parseMessage(request);
            } catch (IOException ex) {
                printStackTrace(ex);
                return;
            }
            callbacks.printOutput("originalRequest: \n" + originalRequest);
            List<Cookie> originalCookies = new ArrayList<>();
            try {
                originalCookies = originalRequest.getCookies();
                callbacks.printOutput("originalCookies: " + originalCookies);
            } catch (Exception e) {
                printStackTrace(e);
            }

            //list to hold the names of cookies that hold session
            List<Cookie> sessionCookies = new ArrayList<>();

            callbacks.printOutput("TESTING " + originalCookies.size() + " cookies...");
            for (int i = 0; i < originalCookies.size(); i++) {
                callbacks.printOutput("Test #" + i);
                try {
                    //make a copy of the original cookies
                    List<Cookie> testCookies = new ArrayList<>(originalCookies);

                    //drop the one cookie 
                    Cookie testCookie = testCookies.remove(i);
                    callbacks.printOutput("Removing cookie: " + testCookie.getName());
                    panel.setCurrentTest(testCookie.getName());
                    originalRequest.setCookies(testCookies);

                    IHttpRequestResponse testRequestResponse = callbacks.makeHttpRequest(service, originalRequest.getBytes());

                    byte[] response = testRequestResponse.getResponse();
                    String responseAsString = new String(response);
                    callbacks.printOutput("RESPONSE:");
                    callbacks.printOutput(responseAsString);

                    if (!responseAsString.contains(timeoutMatchString)) {
                        //we no longer have a valid session 
                        callbacks.printOutput("SESSION COOKIE FOUND! " + testCookie.getName());
                        sessionCookies.add(testCookie);
                        panel.setCookies(sessionCookies);
                    }
                } catch (Exception e) {
                    printStackTrace(e);
                }
            }

            panel.setCurrentTest("DONE!");
            panel.setCookies(sessionCookies);
        }
    }

    private void initializeGUI(IHttpRequestResponse[] requestResponse, String selection) throws HeadlessException {

        SessionDiscoveryPanel discovery = new SessionDiscoveryPanel(this, requestResponse, selection);

        //the whole GUI window
        JFrame gui = new JFrame("Session Discovery");
        gui.setLayout(new BorderLayout());
        gui.add(discovery, BorderLayout.CENTER);
        if (callbacks != null) {
            callbacks.customizeUiComponent(gui);  //apply Burp's styles
        }
        gui.pack();
        gui.setVisible(true);
    }

}
