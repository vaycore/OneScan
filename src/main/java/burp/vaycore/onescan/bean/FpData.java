package burp.vaycore.onescan.bean;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * 指纹数据
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpData implements Serializable {

   /**
    * 指纹名称（产品名）
    */
   private String name;

   /**
    * 产品公司
    */
   private String company;

   /**
    * 编程语言
    */
   private String lang;

   /**
    * 软硬件（0=其它；1=硬件；2=软件）
    */
   private String softHard;

   /**
    * 产品使用的开发框架
    */
   private String frame;

   /**
    * 父类别
    */
   private String parentCategory;

   /**
    * 类别
    */
   private String category;

   /**
    * 指纹规则
    */
   private ArrayList<ArrayList<FpRule>> rules;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public String getLang() {
      return this.lang;
   }

   public void setLang(String lang) {
      this.lang = lang;
   }

   public String getFrame() {
      return this.frame;
   }

   public void setFrame(String frame) {
      this.frame = frame;
   }

   public String getCompany() {
      return this.company;
   }

   public void setCompany(String company) {
      this.company = company;
   }

   public String getSoftHard() {
      return this.softHard;
   }

   public void setSoftHard(String softHard) {
      this.softHard = softHard;
   }

   public String getCategory() {
      return this.category;
   }

   public void setCategory(String category) {
      this.category = category;
   }

   public String getParentCategory() {
      return this.parentCategory;
   }

   public void setParentCategory(String parentCategory) {
      this.parentCategory = parentCategory;
   }

   public ArrayList<ArrayList<FpRule>> getRules() {
      return this.rules;
   }

   public void setRules(ArrayList<ArrayList<FpRule>> rules) {
      this.rules = rules;
   }
}
