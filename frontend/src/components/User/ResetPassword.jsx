import TextField from "@mui/material/TextField";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { resetPassword, clearErrors } from "../../actions/userAction";
import { useSnackbar } from "notistack";
import BackdropLoader from "../Layouts/BackdropLoader";
import MetaData from "../Layouts/MetaData";
import FormSidebar from "./FormSidebar";

const ResetPassword = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { enqueueSnackbar } = useSnackbar();
    const params = useParams();

    const { error, success, loading } = useSelector(
        (state) => state.forgotPassword
    );

    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    const handleSubmit = (e) => {
        e.preventDefault();

        if (newPassword.length < 8) {
            enqueueSnackbar("Mật khẩu phải có ít nhất 8 kí tự", {
                variant: "warning",
            });
            return;
        }
        if (newPassword !== confirmPassword) {
            enqueueSnackbar("Mật khẩu chưa trùng nhau, vui lòng nhập lại!", {
                variant: "error",
            });
            return;
        }

        const formData = new FormData();
        formData.set("password", newPassword);
        formData.set("confirmPassword", confirmPassword);
        dispatch(resetPassword(params.token, formData));
    };

    useEffect(() => {
        if (error) {
            enqueueSnackbar(error, { variant: "error" });
            dispatch(clearErrors());
        }
        if (success) {
            enqueueSnackbar("Thay đổi mật khẩu thành công", {
                variant: "success",
            });
            navigate("/login");
        }
    }, [dispatch, error, success, navigate, enqueueSnackbar]);

    return (
        <>
            {loading && <BackdropLoader />}
            <main class="w-2/4 mt-12 mx-auto sm:pt-20 sm:mt-0">
                {/* <!-- row --> */}
                <div class="flex sm:w-4/6 sm:mt-4 m-auto mb-7 bg-white shadow-lg">
                    {/* <!-- login column --> */}
                    <div class="flex-1 overflow-hidden">
                        <h2 className="text-center text-2xl font-medium mt-6 text-gray-800">
                            Đặt lại mật khẩu
                        </h2>

                        {/* <!-- edit info container --> */}
                        <div class="text-center py-10 px-4 sm:px-14">
                            {/* <!-- input container --> */}
                            <form onSubmit={handleSubmit}>
                                <div class="flex flex-col w-full gap-4">
                                    <TextField
                                        fullWidth
                                        label="Mật khẩu mới"
                                        type="password"
                                        name="newPassword"
                                        value={newPassword}
                                        onChange={(e) =>
                                            setNewPassword(e.target.value)
                                        }
                                        required
                                    />
                                    <TextField
                                        fullWidth
                                        label="Nhập lại mật khẩu"
                                        type="password"
                                        name="confirmPassword"
                                        value={confirmPassword}
                                        onChange={(e) =>
                                            setConfirmPassword(e.target.value)
                                        }
                                        required
                                    />

                                    {/* <!-- button container --> */}
                                    <div class="flex flex-col gap-2.5 mt-2 mb-32">
                                        <p class="text-xs text-primary-grey text-left">
                                            Đồng ý với{" "}
                                            <a
                                                href=""
                                                class="text-primary-blue"
                                            >
                                                {" "}
                                                Điều khoản sử dụng
                                            </a>{" "}
                                            và{" "}
                                            <a
                                                href=""
                                                class="text-primary-blue"
                                            >
                                                {" "}
                                                Chính sách bảo mật
                                            </a>
                                        </p>
                                        <button
                                            type="submit"
                                            class="text-white py-3 w-full bg-primary-blue shadow hover:shadow-lg rounded-sm font-medium"
                                        >
                                            Gửi
                                        </button>
                                    </div>
                                    {/* <!-- button container --> */}
                                </div>
                            </form>
                            {/* <!-- input container --> */}

                            <Link
                                to="/register"
                                class="font-medium text-sm text-primary-blue"
                            >
                                Chưa có tài khoản ? Đăng ký tài khoản mới.
                            </Link>
                        </div>
                        {/* <!-- edit info container --> */}
                    </div>
                    {/* <!-- login column --> */}
                </div>
                {/* <!-- row --> */}
            </main>
        </>
    );
};

export default ResetPassword;
