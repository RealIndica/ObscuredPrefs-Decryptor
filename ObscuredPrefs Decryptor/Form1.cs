using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using Microsoft.Win32;
using CodeStage.AntiCheat;
using CodeStage;
using CodeStage.AntiCheat.Detectors;
using CodeStage.AntiCheat.ObscuredTypes;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

//HKEY_CURRENT_USER\Software\CrazyDevs\Hashiriya

namespace ObscuredPrefs_Decryptor
{
    public partial class Form1 : Form
    {
        RegistryKey loadKey;
        string decryptKey;
        List<byte[]> regKeys = new List<byte[]>();
        List<ListViewItem> listItems = new List<ListViewItem>();
        private ListViewColumnSorter lvwColumnSorter;

        public Form1()
        {
            InitializeComponent();
            lvwColumnSorter = new ListViewColumnSorter();
            this.listView1.ListViewItemSorter = lvwColumnSorter;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            button1.Enabled = false;
            SizeLastColumn(listView1);
            comboBox1.SelectedIndex = 0;
        }

        void updateProgressMax(int max)
        {
            Invoke(new Action(() =>
            {
                progressBar1.Maximum = max;
            }));
        }

        void updateProgress(int percent)
        {
            Invoke(new Action(() =>
            {
                progressBar1.Value = percent;
            }));
        }

        void addListItem(ListViewItem item)
        {
            Invoke(new Action(() =>
           {
               listView1.Items.Add(item);
           }));
        }

        void listBoxBegin()
        {
            Invoke(new Action(() =>
            {
                listView1.BeginUpdate();
            }));
        }

        void listBoxEnd()
        {
            Invoke(new Action(() =>
            {
                listView1.EndUpdate();
            }));
        }

        void listBoxUpdateBinding()
        {
            Invoke(new Action(() =>
            {
                listView1.Items.AddRange(listItems.ToArray());
            }));
        }

        private void button4_Click(object sender, EventArgs e)
        {
            button4.Enabled = false;
            Thread t = new Thread(delegate ()
            {
                textBox1.Text = textBox1.Text.Replace(@"HKEY_CURRENT_USER\", "");

                loadKey = Registry.CurrentUser.OpenSubKey(textBox1.Text);

                updateProgressMax(loadKey.GetValueNames().Count() * 2);

                int percent = 0;

                if (loadKey != null)
                {
                    foreach (string key in loadKey.GetValueNames())
                    {
                        RegistryValueKind keyType = loadKey.GetValueKind(key);
                        ListViewItem item;
                        switch (keyType)
                        {
                            case RegistryValueKind.Binary:
                                item = new ListViewItem(key);
                                item.SubItems.Add(BitConverter.ToString((byte[])loadKey.GetValue(key)));
                                regKeys.Add((byte[])loadKey.GetValue(key));
                                break;
                            case RegistryValueKind.String:
                                item = new ListViewItem(key);
                                item.SubItems.Add(loadKey.GetValue(key).ToString());
                                regKeys.Add(new byte[0]);
                                break;
                            case RegistryValueKind.DWord:
                                item = new ListViewItem(key);
                                item.SubItems.Add(Convert.ToInt32(loadKey.GetValue(key)).ToString());
                                regKeys.Add(new byte[0]);
                                break;
                            default:
                                item = new ListViewItem(key);
                                item.SubItems.Add(loadKey.GetValue(key).ToString());
                                regKeys.Add(new byte[0]);
                                break;
                        }
                        listItems.Add(item);
                        percent++;
                        updateProgress(percent);
                    }

                    foreach (ListViewItem x in listItems)
                    {
                        x.SubItems[0].Text = x.SubItems[0].Text.Substring(0, x.SubItems[0].Text.IndexOf("_"));
                        percent++;
                        updateProgress(percent);
                    }

                    listBoxBegin();
                    listBoxUpdateBinding();
                    listBoxEnd();
                    button1.Enabled = true;
                }
                else
                {
                    MessageBox.Show("Unable to open the registry key provided.");
                }
            });
            t.Start();
        }

        public bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        public byte[] DecryptData(string key, string encryptedInput)
        {
            byte[] array;
            try
            {
                array = Convert.FromBase64String(encryptedInput);
            }
            catch (Exception)
            {
                return null;
            }
            if (array.Length == 0)
            {
                return null;
            }
            int num = array.Length;
            ObscuredPrefs.DeviceLockLevel deviceLockLevel = (ObscuredPrefs.DeviceLockLevel)array[num - 5];
            byte[] array2 = new byte[4];
            Buffer.BlockCopy(array, num - 4, array2, 0, 4);
            uint num2 = (uint)((int)array2[0] | (int)array2[1] << 8 | (int)array2[2] << 16 | (int)array2[3] << 24);
            uint num3 = 0U;
            int num4;
            if (deviceLockLevel != ObscuredPrefs.DeviceLockLevel.None)
            {
                num4 = num - 11;
                if (ObscuredPrefs.lockToDevice != ObscuredPrefs.DeviceLockLevel.None)
                {
                    byte[] array3 = new byte[4];
                    Buffer.BlockCopy(array, num4, array3, 0, 4);
                    num3 = (uint)((int)array3[0] | (int)array3[1] << 8 | (int)array3[2] << 16 | (int)array3[3] << 24);
                }
            }
            else
            {
                num4 = num - 7;
            }
            byte[] array4 = new byte[num4];
            Buffer.BlockCopy(array, 0, array4, 0, num4);
            byte[] array5 = ObscuredPrefs.EncryptDecryptBytes(array4, num4, key + ObscuredPrefs.encryptionKey);
            return array5;
        }

        private string getAllTypes(byte[] decryptedBytes)
        {
            string builtString = "";
            string exceptionStr = "null".applyBrackets();
            try //int
            {
                builtString += BitConverter.ToInt32(decryptedBytes, 0).ToString().applyBrackets();
            }
            catch (Exception) { builtString += exceptionStr; }
            try //uint
            {
                builtString += BitConverter.ToUInt32(decryptedBytes, 0).ToString().applyBrackets();
            }
            catch (Exception) { builtString += exceptionStr; }
            try //float
            {
                builtString += BitConverter.ToSingle(decryptedBytes, 0).ToString().applyBrackets();
            }
            catch (Exception) { builtString += exceptionStr; }
            try //double
            {
                builtString += BitConverter.ToDouble(decryptedBytes, 0).ToString().applyBrackets();
            }
            catch (Exception) { builtString += exceptionStr; }
            try //long
            {
                builtString += BitConverter.ToInt64(decryptedBytes, 0).ToString().applyBrackets();
            }
            catch (Exception) { builtString += exceptionStr; }
            try //bool
            {
                builtString += BitConverter.ToBoolean(decryptedBytes, 0).ToString().applyBrackets();
            }
            catch (Exception) { builtString += exceptionStr; }
            try //vector2 vector3 quat rect
            {
                float x = BitConverter.ToSingle(decryptedBytes, 0);
                float y = BitConverter.ToSingle(decryptedBytes, 4);
                float z = 6699f;
                float w = 6699f;

                try { z = BitConverter.ToSingle(decryptedBytes, 8); } catch (Exception) { }
                try { w = BitConverter.ToSingle(decryptedBytes, 12); } catch (Exception) { }
                if (z == 6699f && w == 6699f) //vector2
                {
                    string p = (x.ToString() + ", " + y.ToString()).applyBrackets();
                    builtString += p;
                }
                else if (z != 6699f && w == 6699f) //vector3
                {
                    string p = (x.ToString() + ", " + y.ToString() + ", " + z.ToString()).applyBrackets();
                    builtString += p;
                }
                else //quat
                {
                    string p = (x.ToString() + ", " + y.ToString() + ", " + z.ToString() + ", " + w.ToString()).applyBrackets();
                    builtString += p;
                }
            }
            catch (Exception) { builtString += exceptionStr; }
            try //string
            {
                builtString += Encoding.UTF8.GetString(decryptedBytes).applyBrackets();
            }
            catch (Exception) { builtString += exceptionStr; }

            return builtString;
        }

        void updateDisplayType(int idx)
        {
            int listItemIdx = 0;
            foreach (ListViewItem mainItem in listView1.Items)
            {
                ListViewItem.ListViewSubItem item = mainItem.SubItems[1];
                try
                {
                    string encryptedPrefsString = Encoding.ASCII.GetString(regKeys[listItemIdx]);
                    encryptedPrefsString = encryptedPrefsString.Remove(encryptedPrefsString.Length - 1);
                    byte[] decryptedBytes = DecryptData(mainItem.Text, encryptedPrefsString);

                    switch (idx)
                    {
                        case 0: //all
                            item.Text = getAllTypes(decryptedBytes);
                            break;
                        case 1: //int
                            item.Text = BitConverter.ToInt32(decryptedBytes, 0).ToString();
                            break;
                        case 2: //uint
                            item.Text = BitConverter.ToUInt32(decryptedBytes, 0).ToString();
                            break;
                        case 3: //string
                            item.Text = Encoding.UTF8.GetString(decryptedBytes);
                            break;
                        case 4: //float
                            item.Text = BitConverter.ToSingle(decryptedBytes, 0).ToString();
                            break;
                        case 5: //double
                            item.Text = BitConverter.ToDouble(decryptedBytes, 0).ToString();
                            break;
                        case 6: //long
                            item.Text = BitConverter.ToInt64(decryptedBytes, 0).ToString();
                            break;
                        case 7: //bool
                            item.Text = BitConverter.ToBoolean(decryptedBytes, 0).ToString();
                            break;
                        case 8: //vector
                            string builtString = "";
                            float x = BitConverter.ToSingle(decryptedBytes, 0);
                            float y = BitConverter.ToSingle(decryptedBytes, 4);
                            float z = 6699f;
                            float w = 6699f;

                            try { z = BitConverter.ToSingle(decryptedBytes, 8); } catch (Exception) { }
                            try { w = BitConverter.ToSingle(decryptedBytes, 12); } catch (Exception) { }
                            if (z == 6699f && w == 6699f) //vector2
                            {
                                string p = (x.ToString() + ", " + y.ToString());
                                builtString += p;
                            }
                            else if (z != 6699f && w == 6699f) //vector3
                            {
                                string p = (x.ToString() + ", " + y.ToString() + ", " + z.ToString());
                                builtString += p;
                            }
                            else //quat
                            {
                                string p = (x.ToString() + ", " + y.ToString() + ", " + z.ToString() + ", " + w.ToString());
                                builtString += p;
                            }
                            item.Text = builtString;
                            break;
                    }
                }
                catch (Exception) { item.Text = "null"; }
                listItemIdx++;
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Thread t = new Thread(delegate ()
            {
                decryptKey = textBox2.Text;
                updateProgressMax(listView1.Items.Count);
                int idx = 0;
                foreach (ListViewItem x in listView1.Items)
                {
                    string value = x.SubItems[0].Text;
                    if (IsBase64String(value))
                    {
                        try
                        {
                            byte[] data = Convert.FromBase64String(value);
                            string decodedString = Encoding.UTF8.GetString(data);
                            value = ObscuredString.EncryptDecrypt(decodedString, decryptKey);
                            x.SubItems[0].Text = value;

                            string encryptedPrefsString = Encoding.ASCII.GetString(regKeys[idx]);
                            encryptedPrefsString = encryptedPrefsString.Remove(encryptedPrefsString.Length - 1);
                            byte[] arr = DecryptData(value, encryptedPrefsString);
                            x.SubItems[1].Text = getAllTypes(arr);
                        }
                        catch (Exception) { }
                    }
                    idx++;
                    updateProgress(idx);
                }
                button1.Enabled = false;
                button5.Enabled = true;
                comboBox1.Enabled = true;
            });
            t.Start();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            List<byte> bytes = new List<byte>();
            var filePath = string.Empty;

            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "dll files (*.dll)|*.dll|All files (*.*)|*.*";
                openFileDialog.Title = "DLL File containing ObscuredPrefs";

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    //Get the path of specified file
                    filePath = openFileDialog.FileName;

                    //Read the contents of the file into a stream
                    bytes = File.ReadAllBytes(filePath).ToList();
                }
            }

            ModuleContext ctx = ModuleDef.CreateModuleContext();
            ModuleDefMD module = ModuleDefMD.Load(bytes.ToArray(), ctx);

            string encryptionKey = "null";

            foreach (TypeDef type in module.Types)
            {
                if (type.FullName == "CodeStage.AntiCheat.ObscuredTypes.ObscuredPrefs")
                {
                    foreach (MethodDef def in type.Methods)
                    {
                        if (def.Name == ".cctor")
                        {
                            foreach (Instruction i in def.Body.Instructions)
                            {
                                if (i.OpCode == OpCodes.Ldstr)
                                {
                                    encryptionKey = i.Operand.ToString();
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (encryptionKey == "null")
            {
                MessageBox.Show("Unable to find the decryption key!\r\n Make sure sure the assembly contains CodeStage.AntiCheat.ObscuredTypes.ObscuredPrefs!");
            } else
            {
                textBox2.Text = encryptionKey;
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            throw new NotImplementedException();
        }

        private void SizeLastColumn(ListView lv)
        {
            lv.Columns[lv.Columns.Count - 1].Width = -2;
        }

        private void listView1_Resize(object sender, EventArgs e)
        {
            SizeLastColumn((ListView)sender);
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            updateDisplayType(comboBox1.SelectedIndex);
        }

        private void button5_Click(object sender, EventArgs e)
        {
            string filename = String.Format("{0}.txt", DateTime.Now.ToString("DUMP yyyy-MM-dd HH.mm.ss"));

            using (StreamWriter sw = new StreamWriter(filename))
            {
                foreach (ListViewItem item in listView1.Items)
                {
                    sw.WriteLine(item.Text + " | " + item.SubItems[1].Text);
                }
            }
            MessageBox.Show("Dumped to " + filename);
        }

        private void listView1_ColumnClick(object sender, ColumnClickEventArgs e)
        {
            if (e.Column == lvwColumnSorter.SortColumn)
            {
                // Reverse the current sort direction for this column.
                if (lvwColumnSorter.Order == SortOrder.Ascending)
                {
                    lvwColumnSorter.Order = SortOrder.Descending;
                }
                else
                {
                    lvwColumnSorter.Order = SortOrder.Ascending;
                }
            }
            else
            {
                // Set the column number that is to be sorted; default to ascending.
                lvwColumnSorter.SortColumn = e.Column;
                lvwColumnSorter.Order = SortOrder.Ascending;
            }

            // Perform the sort with these new sort options.
            this.listView1.Sort();
        }
    }
}
