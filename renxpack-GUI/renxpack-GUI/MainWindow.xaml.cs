using System;
using System.Windows;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;
using Path = System.IO.Path;

namespace RENXPACK_GUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (!is_renxpack_exists())
            {
                System.Windows.Application.Current.Shutdown();
            }

            initializeKeyset();
        }

        private void initializeKeyset()
        {
            if (File.Exists(".\\keys.dat"))
            {
                txt_keyset.Text = Path.GetFullPath(".\\keys.dat");
            }
            else if (File.Exists(".\\keys.txt"))
            {
                txt_keyset.Text = Path.GetFullPath(".\\keys.txt");
            }
            else if (File.Exists(".\\keys.ini"))
            {
                txt_keyset.Text = Path.GetFullPath(".\\keys.ini");
            }
            else if (File.Exists(".\\prod.keys"))
            {
                txt_keyset.Text = Path.GetFullPath(".\\prod.keys");
            }
        }

        private bool is_renxpack_exists()
        {
            if (!(File.Exists(".\\renxpack.exe")))
            {
                System.Windows.MessageBox.Show("renxpack.exe is missing", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            return true;
        }

        private bool check_general_options()
        {
            if (txt_outdir.Text == string.Empty)
            {
                System.Windows.MessageBox.Show("Output directory path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            else if (txt_keyset.Text == string.Empty)
            {
                System.Windows.MessageBox.Show("Keyset path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            else if (txt_nsp.Text == string.Empty)
            {
                System.Windows.MessageBox.Show("reNXpack path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            return true;
        }

        static object x = new object();
        void OnOutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            Process p = sender as Process;
            if (p == null)
                return;
            lock (x)
            {
                Dispatcher.Invoke(() =>
                {
                    txt_log.AppendText(e.Data + Environment.NewLine);
                    txt_log.ScrollToEnd();
                });
            }
        }

        private void launch_renxpack(string args)
        {
            if (is_renxpack_exists() == true && check_general_options() == true)
            {
                btn_convert.IsEnabled = false;
                string renxpack_args;
                renxpack_args = "\"" + txt_nsp.Text + "\" -k \"" + txt_keyset.Text + "\" -o \"" + txt_outdir.Text + "\" " + args;
                Process renxpack = new Process();
                renxpack.StartInfo.FileName = ".\\renxpack.exe";
                renxpack.StartInfo.Arguments = renxpack_args;
                renxpack.StartInfo.UseShellExecute = false;
                renxpack.StartInfo.RedirectStandardOutput = true;
                renxpack.StartInfo.RedirectStandardError = true;
                renxpack.OutputDataReceived += OnOutputDataReceived;
                renxpack.ErrorDataReceived += OnOutputDataReceived;
                renxpack.StartInfo.CreateNoWindow = true;
                renxpack.EnableRaisingEvents = true;
                renxpack.Exited += new EventHandler(has_renxpack_exited);
                renxpack.Start();
                txt_log.Text = "reNXpack execution started. Please wait...\n\n";
                renxpack.BeginOutputReadLine();
                renxpack.BeginErrorReadLine();
            }
        }

        private void has_renxpack_exited(object sender, System.EventArgs e)
        {
            this.Dispatcher.Invoke(() =>
            {
                btn_convert.IsEnabled = true;
            });
        }

        private void browse_folder(ref System.Windows.Controls.TextBox txtbox)
        {
            FolderBrowserDialog browse_dialog = new FolderBrowserDialog();
            DialogResult dialog_result = browse_dialog.ShowDialog();
            if (dialog_result == System.Windows.Forms.DialogResult.OK)
                txtbox.Text = browse_dialog.SelectedPath;
        }

        private void browse_folder(ref System.Windows.Controls.TextBox txtbox, string selectedPath)
        {
            FolderBrowserDialog browse_dialog = new FolderBrowserDialog();
            if (selectedPath != string.Empty)
            {
                browse_dialog.RootFolder = Environment.SpecialFolder.Desktop;
                browse_dialog.SelectedPath = selectedPath;
            }
            DialogResult dialog_result = browse_dialog.ShowDialog();
            if (dialog_result == System.Windows.Forms.DialogResult.OK)
                txtbox.Text = browse_dialog.SelectedPath;
        }

        private void browse_file(ref System.Windows.Controls.TextBox txtbox)
        {
            OpenFileDialog nca_browse_dialog = new OpenFileDialog();
            DialogResult dialog_result = nca_browse_dialog.ShowDialog();
            if (dialog_result == System.Windows.Forms.DialogResult.OK)
            {
                txtbox.Text = nca_browse_dialog.FileName;
                if (txtbox.Name == "txt_nsp" && txt_outdir.Text == string.Empty)
                {
                    txt_outdir.Text = Path.GetDirectoryName(txt_nsp.Text);
                }
            }
        }

        private void btn_browse_outdir_Click(object sender, RoutedEventArgs e)
        {
            if (txt_outdir.Text == string.Empty)
            {
                browse_folder(ref txt_outdir);
            }
            else
            {                
                browse_folder(ref txt_outdir, txt_outdir.Text);
            }            
        }

        private void btn_browse_keyset_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_keyset);
        }

        private void btn_convert_Click(object sender, RoutedEventArgs e)
        {
            txt_log.Text = string.Empty;
            string args = string.Empty;
            if (chk_tempfolder.IsChecked == true)
                args += "-t \"" + txt_outdir.Text + "\\renxpack_extracted_nsp\"";
            launch_renxpack(args);
        }

    private void btn_browse_nsp_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_nsp);
        }
    }
}
