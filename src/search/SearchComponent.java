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
package search;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.*;
import java.util.Base64;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author Carl Sampson <chs@chs.us>
 */
public class SearchComponent extends JPanel
{

    IBurpExtenderCallbacks callbacks;
    BurpExtender extender;
    private JCheckBox jCheckBoxHeader;
    private JCheckBox jCheckBoxBody;
    private JList jListSearchTerms;
    private JTextField jTerm;
    private DefaultListModel<String> model;
    private DefaultTableModel activeModel;

    public SearchComponent(IBurpExtenderCallbacks callbacks, BurpExtender extender)
    {
        this.callbacks = callbacks;
        this.extender = extender;
        this.model = null;

        initComponents();

        this.callbacks.customizeUiComponent(this.jCheckBoxHeader);
        this.callbacks.customizeUiComponent(this.jCheckBoxBody);
        this.callbacks.customizeUiComponent(this.jListSearchTerms);
        restoreSavedSettings();
    }

    public void saveSettings()
    {
        //Enabled/Disabled for headers
        this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_HEADER_ENABLED", null);
        if (this.jCheckBoxHeader.isSelected())
        {
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_HEADER_ENABLED", "ENABLED");
        }

        //Enabled/Disabled for body        
        this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_BODY_ENABLED", null);
        if (this.jCheckBoxBody.isSelected())
        {
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_BODY_ENABLED", "ENABLED");
        }

        //Write search terms to settings
        ListModel listModel = jListSearchTerms.getModel();
        if (listModel.getSize() == 0)
        {
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_TERMS", null);
        }
        else
        {
            ArrayList<String> items = new ArrayList<>();
            for (int i = 0; i < listModel.getSize(); i++)
            {
                String item = (String) listModel.getElementAt(i);
                items.add(Base64.getEncoder().encodeToString(item.getBytes()));
            }
            String values = String.join("|", items);
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_TERMS", values);
        }
    }

    public void restoreSavedSettings()
    {
       //Enabled/Disabled for headers
        boolean enabledSel;
        enabledSel = getSetting("SEARCH_PLUGIN_HEADER_ENABLED");
        this.jCheckBoxHeader.setSelected(enabledSel);

        //Enabled/Disabled for headers
        enabledSel = getSetting("SEARCH_PLUGIN_BODY_ENABLED");
        this.jCheckBoxBody.setSelected(enabledSel);
        
        //Get Strings        
        if (this.callbacks.loadExtensionSetting("SEARCH_PLUGIN_TERMS") != null)
        {           
            this.model = new DefaultListModel<>();
            String setting = this.callbacks.loadExtensionSetting("SEARCH_PLUGIN_TERMS");
            String[] values = setting.split("\\|");
            for (String val : values) {
                String decoded = new String(Base64.getDecoder().decode(val));
                model.addElement(decoded);
            }
            jListSearchTerms.setModel(this.model);
        }
    }
    
    private boolean getSetting(String name)
    {
        if (this.callbacks.loadExtensionSetting(name) != null)
        {
            return this.callbacks.loadExtensionSetting(name).equals("ENABLED") == true;
        }
        else
        {
            return false;
        }
    }

    private void initComponents()
    {
        JLabel jLabel1 = new JLabel();
        jLabel1.setFont(new Font("Tahoma", 1, 16));
        jLabel1.setForeground(new Color(229, 137, 0));
        jLabel1.setText("Passive Search Settings");
        jLabel1.setAlignmentX(CENTER_ALIGNMENT);

        //Headers
        this.jCheckBoxHeader = new JCheckBox();
        this.jCheckBoxHeader.setSelected(true);
        this.jCheckBoxHeader.setText("Header Search");
        this.jCheckBoxHeader.setAlignmentX(CENTER_ALIGNMENT);
        this.jCheckBoxHeader.addActionListener((ActionEvent evt) -> {
            SearchComponent.this.saveSettings();
        });

        //Body
        this.jCheckBoxBody = new JCheckBox();
        this.jCheckBoxBody.setSelected(true);
        this.jCheckBoxBody.setText("Body Search");
        this.jCheckBoxBody.setAlignmentX(CENTER_ALIGNMENT);
        this.jCheckBoxBody.addActionListener((ActionEvent evt) -> {
            SearchComponent.this.saveSettings();
        });

        JPanel jCheckPanel = new JPanel(new FlowLayout());
        jCheckPanel.add(jCheckBoxHeader);
        jCheckPanel.add(jCheckBoxBody);

        JLabel jLabel2 = new JLabel();
        jLabel2.setFont(new Font("Tahoma", 1, 13));
        jLabel2.setForeground(new Color(229, 137, 0));
        jLabel2.setText("Search Items");
        jLabel2.setAlignmentX(CENTER_ALIGNMENT);
        jLabel2.setToolTipText("Right Click to Delete");

        this.jListSearchTerms = new JList();
        jListSearchTerms.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        jListSearchTerms.setLayoutOrientation(JList.VERTICAL);
        jListSearchTerms.setVisibleRowCount(-1);
        JScrollPane jListScroller = new JScrollPane(jListSearchTerms);
        jListScroller.setPreferredSize(new Dimension(500, 160));
        jListScroller.setAlignmentX(CENTER_ALIGNMENT);

        jListSearchTerms.addMouseListener(new MouseAdapter()
        {
            @Override
            public void mouseClicked(MouseEvent evt)
            {
                //Right click delete
                if (evt.getButton() == 3)
                {
                    int index = SearchComponent.this.jListSearchTerms.locationToIndex(evt.getPoint());
                    SearchComponent.this.model.removeElementAt(index);
                    SearchComponent.this.saveSettings();
                }
            }
        });

        BoxLayout layout = new BoxLayout(this, BoxLayout.Y_AXIS);
        setLayout(layout);
        this.add(jLabel1);
        this.add(Box.createRigidArea(new Dimension(0, 10)));
        this.add(jCheckPanel);
        this.add(Box.createRigidArea(new Dimension(0, 10)));
        this.add(jLabel2);
        this.add(jListScroller);

        //Add the next
        JLabel jLabel3 = new JLabel();
        jLabel3.setFont(new Font("Tahoma", 1, 13));
        jLabel3.setForeground(new Color(229, 137, 0));
        jLabel3.setText("Add Search Term: ");
        jLabel3.setAlignmentX(LEFT_ALIGNMENT);

        this.jTerm = new JTextField(20);
        this.jTerm.addActionListener((ActionEvent e) -> {
            //Create if not there
            if (SearchComponent.this.model == null)
            {
                SearchComponent.this.model = new DefaultListModel<>();
                SearchComponent.this.jListSearchTerms.setModel(SearchComponent.this.model);
            }
            
            //Add Text
            if (SearchComponent.this.jTerm.getText().trim().length() != 0)
            {
                SearchComponent.this.model.addElement(SearchComponent.this.jTerm.getText());
                SearchComponent.this.saveSettings();
            }
            this.jTerm.setText("");

        });

        JPanel panel = new JPanel(new FlowLayout());
        panel.add(jLabel3);
        panel.add(jTerm);
        this.add(panel);       
    }

    public DefaultListModel<String> getModel()
    {
        return model;
    }

    public boolean isPassiveHeaderEnabled()
    {
        return jCheckBoxHeader.isSelected();
    }

    public boolean isPassiveBodyEnabled()
    {
        return jCheckBoxBody.isSelected();
    }
}