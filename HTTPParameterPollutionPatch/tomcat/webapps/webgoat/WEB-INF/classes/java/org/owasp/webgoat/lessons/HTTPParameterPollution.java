package org.owasp.webgoat.lessons;

import java.util.*;
import org.apache.ecs.*;
import org.apache.ecs.html.*;
import org.owasp.webgoat.session.WebSession;
import org.owasp.webgoat.session.ECSFactory;
import javax.servlet.http.HttpServletResponse;

/***************************************************************************************************
 * 
 * 
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details,
 * please see http://www.owasp.org/
 * 
 * Copyright (c) 2002 - 2007 Bruce Mayhew
 * 
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 * 
 * Getting Source ==============
 * 
 * Source for this application is maintained at code.google.com, a repository for free software
 * projects.
 * 
 * For details, please see http://code.google.com/p/webgoat/
 * 
 * @author EatMilkBoy
 * @created August 06, 2012
 */ 

public class HTTPParameterPollution extends LessonAdapter
{
	// define a constant for the field name
	private final static String COURSE_ID = "course_id";
	private final static String COURSE_NAME = "course_name";
	private final static String ACTION = "action";
	private final static String SURVEY_RESULT = "survey_result";
	
	private List<String> CourseList;
	private int Step;
	
	private boolean IsNumber(String s)
	{
		try
		{
			Integer.parseInt(s);
			return true;
		}
		catch (Exception e)
		{
			return false;
		}
	}
	
	public void handleRequest(WebSession s)
	{
		// Setting a special action to be able to submit to customized URI
		int action = s.getParser().getIntParameter(ACTION, 0);
		String course_id = s.getParser().getRawParameter(COURSE_ID, "");
		String course_name = s.getParser().getStringParameter(COURSE_NAME, "");
		
		Form form;
		
		CourseList = new ArrayList<String>();
		CourseList.add("HTTP Basic");
		CourseList.add("HTTP Splitting");
		CourseList.add("HTTP Parameter Pollution");
		
		if (action == 1 && CourseList.contains(course_name))
		{
			form = new Form("attack?" + "Screen=" + String.valueOf(getScreenId()) + "&menu=" + getDefaultCategory().getRanking().toString() + "&" + COURSE_ID + "=" + course_id, Form.POST).setName("form").setEncType("");
			Step = 2;
		}
		else
		{
			form = new Form("attack?" + "Screen=" + String.valueOf(getScreenId()) + "&menu=" + getDefaultCategory().getRanking().toString(), Form.POST).setName("form").setEncType("");
			Step = 1;
		}
		
		form.addElement(createContent(s));

		setContent(form);
	}
	
	protected Element createContent(WebSession s)
	{
		ElementContainer ec = new ElementContainer();
		try
		{
			// get some input from the user -- see ParameterParser for details
			String course_id = s.getParser().getRawParameter(COURSE_ID, "");
			String course_name = s.getParser().getStringParameter(COURSE_NAME, "");
			int action = s.getParser().getIntParameter(ACTION, 0);
			String survey_result = s.getParser().getStringParameter(SURVEY_RESULT, "");

			Input input;
			
			input = new Input(Input.TEXT, ACTION, action);
			input.setID(ACTION);
			input.setStyle("display:none;");
			ec.addElement(input);
			
			if (action == 2 && IsNumber(course_id))
			{
				int course_id_int = Integer.parseInt(course_id);
				if (course_id_int <= CourseList.size())
				{
					StringBuffer msg = new StringBuffer();

					msg.append("Your survey result for \"" + CourseList.get(course_id_int - 1) + "\" is: " + survey_result);
					msg.append("\r\n\r\n");

					s.setMessage(msg.toString());
				}
			}
			
			if (Step == 1)
			{
			
				ec.addElement(new P().addElement(new StringElement("Please select a course to survey: ")));
				
				Select select = new Select(COURSE_NAME);
				Option Default = new Option("Please make a selection");
				Default.addElement("Please make a selection");
				if (!CourseList.contains(course_name))
				{
					Default.setSelected(true);
				}
				select.addElement(Default);
				select.setID(COURSE_NAME);
				
				int real_course_id = 0;
				for (int i=0; i<CourseList.size(); i++)
				{   
					String name = CourseList.get(i);
					Option CourseItem = new Option(name);
					CourseItem.addElement(name);
					if (course_name.equals(name))
					{
						CourseItem.setSelected(true);
						real_course_id = i + 1;
					}
					select.addElement(CourseItem);
				}
			
				select.setOnChange("document.getElementById('" + COURSE_ID + "').value = document.getElementById('" + COURSE_NAME + "').selectedIndex");
			
				ec.addElement(select);
				
				input = new Input(Input.TEXT, COURSE_ID, real_course_id);
				input.setID(COURSE_ID);
				input.setStyle("display:none;");
				ec.addElement(input);
				
				input = (Input)ECSFactory.makeButton("Survey");
				input.setOnClick("document.getElementById('" + ACTION + "').value = 1");
				ec.addElement(input);
			}
			else
			{
				if (action == 1)
				{
					String[] arrTokens = course_id.split("&");
					if (IsNumber(arrTokens[0]))
					{
						for (int i = 1; i < arrTokens.length; i++) 
						{
							System.out.println("Token: " + arrTokens[i]);
							if (arrTokens[i].matches("^survey_result=.*"))
							{
								s.setMessage("Good job!<br>This lesson has detected your successful attack, make a select other than you specified survey result and click \"Submit\" to view the result.<br>");
								// Tell the lesson tracker the lesson has completed.
								// This should occur when the user has 'hacked' the lesson.
								makeSuccess(s);
								break;
							}
						}
					}
				}
				
				ec.addElement(new StringElement("Please provide your opinion for course: <b>" + course_name + "</b>"));
				ec.addElement(new BR());
				ec.addElement(new BR());

				input = new Input(Input.RADIO, SURVEY_RESULT, "Good");
				input.addElement("Good");
				if (action != 1 || (action == 1 && survey_result.equals("Good")))
					input.setChecked(true);
				ec.addElement(input);
				ec.addElement(new BR());
				ec.addElement(new BR());

				input = new Input(Input.RADIO, SURVEY_RESULT, "So-so");
				input.addElement("So-so");
				if (action == 1 && survey_result.equals("So-so"))
					input.setChecked(true);
				ec.addElement(input);
				ec.addElement(new BR());
				ec.addElement(new BR());
				
				input = new Input(Input.RADIO, SURVEY_RESULT, "Bad");
				input.addElement("Bad");
				if (action == 1 && survey_result.equals("Bad"))
					input.setChecked(true);
				ec.addElement(input);
				ec.addElement(new BR());
				ec.addElement(new BR());
				
				input = (Input)ECSFactory.makeButton("Submit");
				input.setOnClick("document.getElementById('" + ACTION + "').value = 2");
				ec.addElement(input);
			}
		}
		catch (Exception e)
		{
			s.setMessage("Error generating " + this.getClass().getName());
			e.printStackTrace();
		}
		return (ec);
	}

	protected Category getDefaultCategory()
	{
		return Category.GENERAL;
	}
	
	private final static Integer DEFAULT_RANKING = new Integer(30);

	protected Integer getDefaultRanking()
	{
		return DEFAULT_RANKING;
	}

	protected List<String> getHints(WebSession s)
	{

		List<String> hints = new ArrayList<String>();
		hints.add("Try inject code into course_id parameter.");
		return hints;

	}

	public String getTitle()
	{
		return ("HTTP Parameter Pollution");
	}
}